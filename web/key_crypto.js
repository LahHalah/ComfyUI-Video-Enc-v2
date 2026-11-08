/* Browser-only P-256 key wrapping helpers for ComfyUI's native UI path.
 * This module unwraps only the one-job password envelope. It does not decrypt
 * the ZIP archive or the inner video stream.
 */
const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

export function lahhalahBase64UrlEncode(bytes) {
    let binary = "";
    for (const byte of new Uint8Array(bytes)) binary += String.fromCharCode(byte);
    return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function lahhalahBase64UrlDecode(value) {
    if (typeof value !== "string" || !/^[A-Za-z0-9_-]+$/.test(value)) {
        throw new Error("Invalid base64url field in wrapped password.");
    }
    const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
    const padded = normalized + "=".repeat((4 - normalized.length % 4) % 4);
    const binary = atob(padded);
    return Uint8Array.from(binary, (char) => char.charCodeAt(0));
}

/** Generate one non-extractable P-256 private key session for a single job. */
export async function createLahHalahBrowserKeySession() {
    if (!globalThis.crypto?.subtle || !globalThis.isSecureContext) {
        throw new Error("Web Crypto requires HTTPS or localhost. Open ComfyUI through a secure origin.");
    }
    const keyPair = await crypto.subtle.generateKey(
        { name: "ECDH", namedCurve: "P-256" },
        false,
        ["deriveBits"],
    );
    const publicRaw = await crypto.subtle.exportKey("raw", keyPair.publicKey);
    const publicKeyBase64Url = lahhalahBase64UrlEncode(publicRaw);
    if (publicKeyBase64Url.length !== 87) {
        throw new Error("Browser generated an unexpected P-256 public key encoding.");
    }
    return Object.freeze({
        publicKeyBase64Url,
        privateKey: keyPair.privateKey,
        createdAt: Date.now(),
    });
}

/** Unwrap the generated password in this browser; does not decrypt any file. */
export async function unwrapLahHalahWrappedPassword(wrapped, privateKey) {
    if (!wrapped || wrapped.version !== 2 || wrapped.curve !== "P-256"
        || wrapped.kdf !== "HKDF-SHA256" || wrapped.cipher !== "AES-256-GCM") {
        throw new Error("Unsupported LahHalah wrapped-password format.");
    }
    if (!privateKey) throw new Error("LahHalah private browser key is unavailable.");

    const ephemeralRaw = lahhalahBase64UrlDecode(wrapped.ephemeral_public_key);
    if (ephemeralRaw.length !== 65 || ephemeralRaw[0] !== 0x04) {
        throw new Error("Invalid ephemeral P-256 public key.");
    }
    const ephemeralPublic = await crypto.subtle.importKey(
        "raw",
        ephemeralRaw,
        { name: "ECDH", namedCurve: "P-256" },
        false,
        [],
    );
    const sharedSecret = await crypto.subtle.deriveBits(
        { name: "ECDH", public: ephemeralPublic },
        privateKey,
        256,
    );
    const hkdfKey = await crypto.subtle.importKey("raw", sharedSecret, "HKDF", false, ["deriveKey"]);
    const info = textEncoder.encode(
        "LahHalah.ComfyUI-Video-Enc.V2/password-wrap/" + wrapped.job_id,
    );
    const wrappingKey = await crypto.subtle.deriveKey(
        {
            name: "HKDF",
            hash: "SHA-256",
            salt: lahhalahBase64UrlDecode(wrapped.salt),
            info,
        },
        hkdfKey,
        { name: "AES-GCM", length: 256 },
        false,
        ["decrypt"],
    );
    const aad = textEncoder.encode("LahHalah.VideoEnc.V2:" + wrapped.job_id);
    const clear = await crypto.subtle.decrypt(
        {
            name: "AES-GCM",
            iv: lahhalahBase64UrlDecode(wrapped.nonce),
            additionalData: aad,
            tagLength: 128,
        },
        wrappingKey,
        lahhalahBase64UrlDecode(wrapped.ciphertext),
    );
    return textDecoder.decode(clear);
}
