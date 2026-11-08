"""Bounded, expiring in-memory preview storage for LahHalah Video Enc.

Preview bytes are kept only in process memory. They are never written to a file.
The cache uses 256-bit capability tokens, short TTLs, a global memory budget,
active-job reservations, and reader leases so in-flight downloads remain accounted.
"""
from __future__ import annotations

import secrets
import threading
import time
from collections import OrderedDict
from typing import BinaryIO, Optional

PREVIEW_CACHE_MAX_BYTES = 256 * 1024 * 1024
PREVIEW_CACHE_MAX_ITEMS = 4
PREVIEW_STREAM_CHUNK_BYTES = 256 * 1024

_LOCK = threading.RLock()
_PREVIEWS = OrderedDict()  # token -> {data, size, expires_at, readers}
_STORED_BYTES = 0
_RESERVED_BYTES = 0
_CLEANUP_STOP = threading.Event()
_CLEANUP_THREAD = None


class PreviewCaptureReader:
    """Pass-through reader that retains a bounded copy of the bytes it reads."""

    def __init__(self, source: BinaryIO, max_bytes: int, memory_guard=None):
        if max_bytes <= 0:
            raise ValueError("max_bytes must be positive")
        self.source = source
        self.max_bytes = int(max_bytes)
        self.memory_guard = memory_guard
        self.buffer: Optional[bytearray] = bytearray()
        self.status = "capturing"
        self.total_seen = 0

    def read(self, size: int = -1) -> bytes:
        chunk = self.source.read(size)
        if not chunk:
            if self.status == "capturing":
                self.status = "captured"
            return chunk

        self.total_seen += len(chunk)
        if self.buffer is not None:
            if self.memory_guard is not None and self.memory_guard():
                self.buffer = None
                self.status = "memory_pressure"
            elif len(self.buffer) + len(chunk) > self.max_bytes:
                self.buffer = None
                self.status = "size_limit_exceeded"
            else:
                self.buffer.extend(chunk)
        return chunk

    def take(self) -> Optional[bytearray]:
        if self.status != "captured" or self.buffer is None or not self.buffer:
            self.buffer = None
            return None
        result = self.buffer
        self.buffer = None
        return result

    def discard(self) -> None:
        self.buffer = None
        if self.status in {"capturing", "captured"}:
            self.status = "discarded"


def _delete_locked(token: str) -> None:
    global _STORED_BYTES
    item = _PREVIEWS.pop(token, None)
    if item is not None:
        _STORED_BYTES = max(0, _STORED_BYTES - item["size"])


def _purge_expired_locked(now: float) -> None:
    for token, item in list(_PREVIEWS.items()):
        if item["expires_at"] <= now and item["readers"] == 0:
            _delete_locked(token)


def _evict_oldest_locked() -> bool:
    for token, item in list(_PREVIEWS.items()):
        if item["readers"] == 0:
            _delete_locked(token)
            return True
    return False


def reserve_preview_capacity(max_bytes: int) -> bool:
    """Reserve global RAM budget before a workflow starts capturing plaintext."""
    global _RESERVED_BYTES
    max_bytes = int(max_bytes)
    if max_bytes <= 0 or max_bytes > PREVIEW_CACHE_MAX_BYTES:
        return False
    with _LOCK:
        _purge_expired_locked(time.monotonic())
        while (
            _STORED_BYTES + _RESERVED_BYTES + max_bytes > PREVIEW_CACHE_MAX_BYTES
            or len(_PREVIEWS) >= PREVIEW_CACHE_MAX_ITEMS
        ):
            if not _evict_oldest_locked():
                return False
        _RESERVED_BYTES += max_bytes
        return True


def release_preview_reservation(reserved_bytes: int) -> None:
    global _RESERVED_BYTES
    with _LOCK:
        _RESERVED_BYTES = max(0, _RESERVED_BYTES - max(0, int(reserved_bytes)))


def publish_preview(data: bytearray, ttl_seconds: int, reserved_bytes: int) -> Optional[str]:
    """Publish captured preview, converting its reservation into cached bytes."""
    global _STORED_BYTES, _RESERVED_BYTES
    size = len(data)
    reserved_bytes = max(0, int(reserved_bytes))
    with _LOCK:
        _RESERVED_BYTES = max(0, _RESERVED_BYTES - reserved_bytes)
        _purge_expired_locked(time.monotonic())
        if size <= 0 or size > reserved_bytes or size > PREVIEW_CACHE_MAX_BYTES:
            return None
        while (
            _STORED_BYTES + _RESERVED_BYTES + size > PREVIEW_CACHE_MAX_BYTES
            or len(_PREVIEWS) >= PREVIEW_CACHE_MAX_ITEMS
        ):
            if not _evict_oldest_locked():
                return None
        token = secrets.token_urlsafe(32)
        while token in _PREVIEWS:
            token = secrets.token_urlsafe(32)
        _PREVIEWS[token] = {
            "data": data,
            "size": size,
            "expires_at": time.monotonic() + max(1, int(ttl_seconds)),
            "readers": 0,
        }
        _STORED_BYTES += size
        return token


def acquire_preview(token: str) -> Optional[bytearray]:
    """Acquire a read lease; the entry cannot be evicted until released."""
    if not isinstance(token, str) or len(token) != 43:
        return None
    with _LOCK:
        now = time.monotonic()
        _purge_expired_locked(now)
        item = _PREVIEWS.get(token)
        if item is None or item.get("revoked") or item["expires_at"] <= now:
            return None
        item["readers"] += 1
        return item["data"]


def release_preview_lease(token: str) -> None:
    with _LOCK:
        item = _PREVIEWS.get(token)
        if item is None:
            return
        item["readers"] = max(0, item["readers"] - 1)
        if item["readers"] == 0 and (item["expires_at"] <= time.monotonic() or item.get("revoked")):
            _delete_locked(token)


def revoke_preview(token: str) -> None:
    with _LOCK:
        item = _PREVIEWS.get(token)
        if item is None:
            return
        item["revoked"] = True
        item["expires_at"] = 0
        if item["readers"] == 0:
            _delete_locked(token)


def clear_preview_cache() -> None:
    global _STORED_BYTES
    with _LOCK:
        # In-flight response handlers hold their own bytearray references. Clearing
        # the cache prevents new requests; their leases are released on completion.
        _PREVIEWS.clear()
        _STORED_BYTES = 0


def _cleanup_loop() -> None:
    while not _CLEANUP_STOP.wait(15):
        with _LOCK:
            _purge_expired_locked(time.monotonic())


def start_preview_cleanup_worker() -> None:
    global _CLEANUP_THREAD
    if _CLEANUP_THREAD is not None and _CLEANUP_THREAD.is_alive():
        return
    _CLEANUP_STOP.clear()
    _CLEANUP_THREAD = threading.Thread(
        target=_cleanup_loop, name="lahhalah-preview-ttl", daemon=True
    )
    _CLEANUP_THREAD.start()


def stop_preview_cleanup_worker() -> None:
    _CLEANUP_STOP.set()
    clear_preview_cache()


def preview_cache_stats() -> dict:
    with _LOCK:
        _purge_expired_locked(time.monotonic())
        return {
            "items": len(_PREVIEWS),
            "stored_bytes": _STORED_BYTES,
            "reserved_bytes": _RESERVED_BYTES,
            "max_bytes": PREVIEW_CACHE_MAX_BYTES,
        }
