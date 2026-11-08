import { app } from "../../scripts/app.js";
import { createLahHalahBrowserKeySession, unwrapLahHalahWrappedPassword } from "./key_crypto.js";

const NODE_NAME = "LahHalahVideoEncryptor";
const MAX_PENDING_KEY_SESSIONS = 12;
const MAX_KEY_SESSION_AGE_MS = 30 * 60 * 1000;
const pendingKeySessions = new WeakMap();
async function createComfyUiKeySession(node) {
    let queue = pendingKeySessions.get(node);
    if (!queue) {
        queue = [];
        pendingKeySessions.set(node, queue);
    }

    const now = Date.now();
    for (let i = queue.length - 1; i >= 0; i--) {
        if (now - queue[i].createdAt > MAX_KEY_SESSION_AGE_MS) queue.splice(i, 1);
    }
    if (queue.length >= MAX_PENDING_KEY_SESSIONS) {
        throw new Error("Too many pending LahHalah key sessions. Finish or clear previous queued jobs first.");
    }

    const session = await createLahHalahBrowserKeySession();
    // The private CryptoKey is non-extractable and stays only in this browser tab.
    queue.push(session);
    return session.publicKeyBase64Url;
}

async function unwrapPasswordForNode(node, wrapped) {
    const queue = pendingKeySessions.get(node) || [];
    const now = Date.now();
    for (let i = queue.length - 1; i >= 0; i--) {
        const session = queue[i];
        if (now - session.createdAt > MAX_KEY_SESSION_AGE_MS) {
            queue.splice(i, 1);
            continue;
        }
        try {
            const password = await unwrapLahHalahWrappedPassword(wrapped, session.privateKey);
            queue.splice(i, 1);
            if (queue.length === 0) pendingKeySessions.delete(node);
            return password;
        } catch {
            // A node may have more than one queued job. Try its other one-job keys.
        }
    }
    if (queue.length === 0) pendingKeySessions.delete(node);
    return null;
}

function installAutomaticKeySerializer(node) {
    const widget = node.widgets?.find((item) => item.name === "frontend_public_key");
    if (!widget || widget.__lahhalahAutoKeyInstalled) return;

    // The workflow keeps an empty value. graphToPrompt awaits serializeValue and
    // receives a fresh key for this execution only; the private key never enters
    // the prompt, workflow JSON, or ComfyUI history.
    widget.value = "";
    widget.label = "frontend_public_key (automatic)";
    if (widget.options) {
        widget.options.placeholder = "Auto-generated for ComfyUI UI; external API clients inject their own";
    }
    widget.serializeValue = async () => createComfyUiKeySession(node);
    widget.__lahhalahAutoKeyInstalled = true;
}

function makeArchiveUrl(fileInfo) {
    const params = new URLSearchParams({
        filename: fileInfo.filename,
        subfolder: fileInfo.subfolder || "",
        type: fileInfo.type || "output",
    });
    return `/view?${params.toString()}`;
}

function removeOldWidget(node) {
    const oldIndex = node.widgets?.findIndex((widget) => widget.name === "lahhalah_secure_result") ?? -1;
    if (oldIndex < 0) return;
    const oldWidget = node.widgets[oldIndex];
    try {
        oldWidget.onRemove?.();
    } finally {
        node.widgets.splice(oldIndex, 1);
    }
}

function addPasswordPanel(root, node, item) {
    const panel = document.createElement("div");
    panel.style.display = "flex";
    panel.style.flexDirection = "column";
    panel.style.gap = "6px";
    panel.style.padding = "8px";
    panel.style.border = "1px solid rgba(130, 180, 150, 0.45)";
    panel.style.borderRadius = "5px";

    const title = document.createElement("strong");
    title.textContent = "Decryption password";
    panel.appendChild(title);

    const status = document.createElement("small");
    status.textContent = "Unwrapping the one-job password in this browser…";
    status.style.opacity = "0.85";
    panel.appendChild(status);

    const passwordInput = document.createElement("input");
    passwordInput.type = "password";
    passwordInput.readOnly = true;
    passwordInput.autocomplete = "off";
    passwordInput.spellcheck = false;
    passwordInput.style.width = "100%";
    passwordInput.style.boxSizing = "border-box";
    passwordInput.style.padding = "7px";
    passwordInput.style.fontFamily = "monospace";
    passwordInput.style.display = "none";
    panel.appendChild(passwordInput);

    const actions = document.createElement("div");
    actions.style.display = "flex";
    actions.style.gap = "6px";
    actions.style.flexWrap = "wrap";

    const reveal = document.createElement("button");
    reveal.type = "button";
    reveal.textContent = "Show password";
    reveal.disabled = true;

    const copy = document.createElement("button");
    copy.type = "button";
    copy.textContent = "Copy password";
    copy.disabled = true;

    reveal.addEventListener("click", () => {
        const show = passwordInput.type === "password";
        passwordInput.type = show ? "text" : "password";
        reveal.textContent = show ? "Hide password" : "Show password";
    });
    copy.addEventListener("click", async () => {
        try {
            await navigator.clipboard.writeText(passwordInput.value);
            status.textContent = "Password copied. Keep it private; it is required to decrypt the ZIP.";
        } catch {
            status.textContent = "Clipboard access was blocked. Reveal the password and copy it manually.";
        }
    });
    actions.append(reveal, copy);
    panel.appendChild(actions);
    root.appendChild(panel);

    let disposed = false;
    unwrapPasswordForNode(node, item.wrapped_secret)
        .then((password) => {
            if (disposed) return;
            if (!password) {
                status.textContent = "No ComfyUI browser key was found. This job was likely submitted by an external API frontend; retrieve the password in that frontend.";
                return;
            }
            passwordInput.value = password;
            passwordInput.style.display = "block";
            reveal.disabled = false;
            copy.disabled = false;
            status.textContent = "Password unlocked in this browser only. It is not returned as plaintext in ComfyUI history.";
        })
        .catch((error) => {
            if (disposed) return;
            status.textContent = `Could not unlock password: ${error.message}`;
        });

    return () => {
        disposed = true;
        passwordInput.value = "";
        status.textContent = "";
    };
}

app.registerExtension({
    name: "LahHalah.VideoEncV2.AutoKeySafePreview",
    async beforeRegisterNodeDef(nodeType, nodeData) {
        if (nodeData.name !== NODE_NAME) return;

        const originalOnNodeCreated = nodeType.prototype.onNodeCreated;
        nodeType.prototype.onNodeCreated = function (...args) {
            const result = originalOnNodeCreated?.apply(this, args);
            installAutomaticKeySerializer(this);
            return result;
        };

        const originalOnConfigure = nodeType.prototype.onConfigure;
        nodeType.prototype.onConfigure = function (...args) {
            const result = originalOnConfigure?.apply(this, args);
            installAutomaticKeySerializer(this);
            return result;
        };

        const originalOnExecuted = nodeType.prototype.onExecuted;
        nodeType.prototype.onExecuted = function (message) {
            originalOnExecuted?.apply(this, arguments);
            removeOldWidget(this);

            const item = message?.secure_video?.[0];
            if (!item) return;

            const root = document.createElement("div");
            root.style.display = "flex";
            root.style.flexDirection = "column";
            root.style.gap = "8px";
            root.style.padding = "8px";
            root.style.width = "100%";
            root.style.boxSizing = "border-box";
            root.style.background = "rgba(30, 30, 30, 0.55)";
            root.style.borderRadius = "6px";

            const status = document.createElement("div");
            status.textContent = item.status === "success"
                ? `Encrypted archive ready: ${item.filename}`
                : `Encryption failed: ${item.status || "unknown error"}`;
            status.style.whiteSpace = "normal";
            status.style.wordBreak = "break-word";
            root.appendChild(status);

            let clearPasswordPanel = null;
            if (item.status === "success" && item.wrapped_secret) {
                clearPasswordPanel = addPasswordPanel(root, this, item);
            }

            if (item.status === "success" && item.filename) {
                const link = document.createElement("a");
                link.href = makeArchiveUrl(item);
                link.textContent = "Download encrypted ZIP";
                link.download = item.filename;
                link.style.display = "inline-block";
                link.style.padding = "7px 10px";
                link.style.borderRadius = "4px";
                link.style.background = "#315d43";
                link.style.color = "white";
                link.style.textDecoration = "none";
                link.style.textAlign = "center";
                root.appendChild(link);

                const note = document.createElement("small");
                note.textContent = "ComfyUI UI runs generate and unwrap a one-job password automatically in this browser. External API frontends provide their own public key. Safe Preview is held temporarily in server RAM.";
                note.style.opacity = "0.8";
                note.style.whiteSpace = "normal";
                root.appendChild(note);

                if (item.preview_status === "available" && item.preview_url && item.preview_token) {
                    const previewLabel = document.createElement("div");
                    previewLabel.textContent = "Safe Preview (temporary RAM copy)";
                    previewLabel.style.fontWeight = "600";
                    root.appendChild(previewLabel);

                    const video = document.createElement("video");
                    video.controls = true;
                    video.playsInline = true;
                    video.preload = "metadata";
                    video.style.width = "100%";
                    video.style.maxHeight = "280px";
                    video.style.borderRadius = "5px";
                    video.style.background = "#000";
                    root.appendChild(video);

                    const previewStatus = document.createElement("small");
                    previewStatus.textContent = `Fetching preview from RAM (expires in ${Math.ceil((item.preview_ttl_seconds || 0) / 60)} min)…`;
                    previewStatus.style.opacity = "0.8";
                    root.appendChild(previewStatus);

                    const downloadPreview = document.createElement("a");
                    downloadPreview.textContent = "Download preview to this device";
                    downloadPreview.style.display = "none";
                    downloadPreview.style.padding = "6px 9px";
                    downloadPreview.style.borderRadius = "4px";
                    downloadPreview.style.background = "#454545";
                    downloadPreview.style.color = "white";
                    downloadPreview.style.textDecoration = "none";
                    downloadPreview.style.textAlign = "center";
                    root.appendChild(downloadPreview);

                    const controller = new AbortController();
                    let blobUrl = null;
                    let disposed = false;

                    const widget = this.addDOMWidget("lahhalah_secure_result", "secure_result", root, {
                        serialize: false,
                        hideOnZoom: false,
                    });
                    const originalOnRemove = widget?.onRemove;
                    if (widget) {
                        widget.onRemove = function () {
                            disposed = true;
                            controller.abort();
                            clearPasswordPanel?.();
                            if (blobUrl) {
                                URL.revokeObjectURL(blobUrl);
                                blobUrl = null;
                            }
                            originalOnRemove?.apply(this, arguments);
                        };
                    }
                    this.setSize([Math.max(this.size[0], 360), Math.max(this.size[1], 540)]);

                    const previewEndpoint = new URL(item.preview_url, window.location.href);
                    fetch(previewEndpoint.toString(), {
                        method: "GET",
                        headers: { Authorization: `Bearer ${item.preview_token}` },
                        credentials: "same-origin",
                        cache: "no-store",
                        referrerPolicy: "no-referrer",
                        signal: controller.signal,
                    })
                        .then((response) => {
                            if (!response.ok) {
                                throw new Error(response.status === 404
                                    ? "Preview expired or was evicted from RAM. Run the node again."
                                    : `Preview request failed (${response.status}).`);
                            }
                            return response.blob();
                        })
                        .then((blob) => {
                            if (disposed) return;
                            if (!blob.size || blob.type && !blob.type.includes("video")) {
                                throw new Error("Server returned an invalid preview payload.");
                            }
                            blobUrl = URL.createObjectURL(blob);
                            video.src = blobUrl;
                            video.load();
                            downloadPreview.href = blobUrl;
                            downloadPreview.download = "lahhalah-preview.mp4";
                            downloadPreview.style.display = "block";
                            previewStatus.textContent = "Preview loaded into this browser. Server-side copy expires automatically.";
                        })
                        .catch((error) => {
                            if (disposed || error.name === "AbortError") return;
                            previewStatus.textContent = `Preview unavailable: ${error.message}`;
                            console.warn("LahHalah Safe Preview:", error);
                        });
                    return;
                }

                const previewStatus = document.createElement("small");
                const previewMessages = {
                    disabled: "Safe Preview is disabled.",
                    memory_budget_full: "Safe Preview skipped: global RAM preview budget is full.",
                    size_limit_exceeded: "Safe Preview skipped: video exceeded the configured preview size limit.",
                    memory_pressure: "Safe Preview stopped to protect available RAM.",
                    invalid_or_empty_mp4: "Safe Preview unavailable: MP4 validation failed.",
                };
                previewStatus.textContent = previewMessages[item.preview_status] || `Safe Preview: ${item.preview_status || "unavailable"}.`;
                previewStatus.style.opacity = "0.8";
                root.appendChild(previewStatus);
            }

            const widget = this.addDOMWidget("lahhalah_secure_result", "secure_result", root, {
                serialize: false,
                hideOnZoom: false,
            });
            const originalOnRemove = widget?.onRemove;
            if (widget) {
                widget.onRemove = function () {
                    clearPasswordPanel?.();
                    originalOnRemove?.apply(this, arguments);
                };
            }
            this.setSize([Math.max(this.size[0], 360), Math.max(this.size[1], 300)]);
        };
    },

    nodeCreated(node) {
        if (node.comfyClass === NODE_NAME || node.type === NODE_NAME) {
            installAutomaticKeySerializer(node);
        }
    },

    loadedGraphNode(node) {
        if (node.comfyClass === NODE_NAME || node.type === NODE_NAME) {
            installAutomaticKeySerializer(node);
        }
    },

    setup(comfyApp) {
        for (const node of comfyApp.graph?._nodes || []) {
            if (node.comfyClass === NODE_NAME || node.type === NODE_NAME) {
                installAutomaticKeySerializer(node);
            }
        }
    },
});
