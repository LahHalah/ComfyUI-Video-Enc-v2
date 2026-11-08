from __future__ import annotations

import base64
import json
import os
import struct
from typing import BinaryIO, Dict, Any

from argon2.low_level import Type, hash_secret_raw
from nacl.bindings import (
    crypto_secretstream_xchacha20poly1305_TAG_FINAL,
    crypto_secretstream_xchacha20poly1305_TAG_MESSAGE,
    crypto_secretstream_xchacha20poly1305_init_push,
    crypto_secretstream_xchacha20poly1305_push,
    crypto_secretstream_xchacha20poly1305_state,
)

MAGIC = b"LAHHALAH-ENC-V2\n"
FORMAT_VERSION = 2
CHUNK_SIZE = 256 * 1024
MAX_HEADER_SIZE = 16 * 1024
KDF_PARAMETERS = {
    "name": "argon2id",
    "time_cost": 3,
    "memory_kib": 65536,
    "parallelism": 2,
    "hash_len": 32,
}


def b64u_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def b64u_decode(value: str) -> bytes:
    if not isinstance(value, str) or not value or len(value) > 8192:
        raise ValueError("Invalid base64url value")
    padding = "=" * ((4 - len(value) % 4) % 4)
    try:
        return base64.b64decode((value + padding).encode("ascii"), altchars=b"-_", validate=True)
    except Exception as exc:
        raise ValueError("Invalid base64url value") from exc


def derive_stream_key(password: bytes, salt: bytes, kdf: Dict[str, Any]) -> bytes:
    if not isinstance(password, bytes) or not password:
        raise ValueError("Password cannot be empty")
    if len(salt) != 16:
        raise ValueError("Invalid Argon2id salt")
    if kdf != KDF_PARAMETERS:
        raise ValueError("Unsupported or non-canonical Argon2id parameters")
    time_cost = int(kdf.get("time_cost", 0))
    memory_kib = int(kdf.get("memory_kib", 0))
    parallelism = int(kdf.get("parallelism", 0))
    hash_len = int(kdf.get("hash_len", 0))
    if not (1 <= time_cost <= 10):
        raise ValueError("Unsupported Argon2id time_cost")
    if not (32768 <= memory_kib <= 262144):
        raise ValueError("Unsupported Argon2id memory_kib")
    if not (1 <= parallelism <= 8) or hash_len != 32:
        raise ValueError("Unsupported Argon2id parameters")
    return hash_secret_raw(
        secret=password, salt=salt, time_cost=time_cost,
        memory_cost=memory_kib, parallelism=parallelism,
        hash_len=hash_len, type=Type.ID,
    )


def encrypt_stream(source: BinaryIO, destination: BinaryIO, password: bytes) -> Dict[str, Any]:
    """Encrypt a file-like stream using versioned libsodium Secretstream."""
    salt = os.urandom(16)
    kdf = dict(KDF_PARAMETERS)
    key = derive_stream_key(password, salt, kdf)
    state = crypto_secretstream_xchacha20poly1305_state()
    secretstream_header = crypto_secretstream_xchacha20poly1305_init_push(state, key)
    header = {
        "format": "lahhalah-secretstream",
        "version": FORMAT_VERSION,
        "cipher": "xchacha20-poly1305-secretstream",
        "kdf": kdf,
        "salt": b64u_encode(salt),
        "secretstream_header": b64u_encode(secretstream_header),
        "chunk_size": CHUNK_SIZE,
    }
    encoded_header = json.dumps(header, separators=(",", ":"), sort_keys=True).encode("utf-8")
    if len(encoded_header) > MAX_HEADER_SIZE:
        raise ValueError("Internal encrypted header is too large")

    destination.write(MAGIC)
    destination.write(struct.pack(">I", len(encoded_header)))
    destination.write(encoded_header)

    counter = 0
    while True:
        raw = source.read(CHUNK_SIZE)
        if not raw:
            break
        associated_data = MAGIC + counter.to_bytes(8, "big")
        encrypted = crypto_secretstream_xchacha20poly1305_push(
            state, raw, ad=associated_data,
            tag=crypto_secretstream_xchacha20poly1305_TAG_MESSAGE,
        )
        destination.write(struct.pack(">I", len(encrypted)))
        destination.write(encrypted)
        counter += 1

    final_ad = MAGIC + counter.to_bytes(8, "big")
    final_chunk = crypto_secretstream_xchacha20poly1305_push(
        state, b"", ad=final_ad,
        tag=crypto_secretstream_xchacha20poly1305_TAG_FINAL,
    )
    destination.write(struct.pack(">I", len(final_chunk)))
    destination.write(final_chunk)
    return {"chunk_count": counter, "salt": b64u_encode(salt)}
