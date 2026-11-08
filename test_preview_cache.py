import io
import os
import sys
import time
import unittest

ROOT = os.path.dirname(os.path.dirname(__file__))
sys.path.insert(0, ROOT)

import preview_cache as pc


class PreviewCacheTests(unittest.TestCase):
    def tearDown(self):
        pc.clear_preview_cache()

    def test_capture_is_passthrough_and_retains_same_bytes(self):
        payload = b"\x00\x00\x00\x18ftyp" + (b"x" * 5000)
        reader = pc.PreviewCaptureReader(io.BytesIO(payload), 8192)
        chunks = []
        while True:
            chunk = reader.read(1024)
            if not chunk:
                break
            chunks.append(chunk)
        self.assertEqual(b"".join(chunks), payload)
        self.assertEqual(reader.status, "captured")
        self.assertEqual(bytes(reader.take()), payload)

    def test_over_limit_drops_preview_but_keeps_stream(self):
        payload = b"A" * 4096
        reader = pc.PreviewCaptureReader(io.BytesIO(payload), 2048)
        returned = reader.read(4096)
        self.assertEqual(returned, payload)
        self.assertEqual(reader.read(1), b"")
        self.assertEqual(reader.status, "size_limit_exceeded")
        self.assertIsNone(reader.take())

    def test_memory_guard_drops_preview(self):
        reader = pc.PreviewCaptureReader(io.BytesIO(b"hello"), 1024, memory_guard=lambda: True)
        self.assertEqual(reader.read(10), b"hello")
        self.assertEqual(reader.read(1), b"")
        self.assertEqual(reader.status, "memory_pressure")
        self.assertIsNone(reader.take())

    def test_token_is_bearer_capability_and_lease_holds_item(self):
        reserved = 4096
        self.assertTrue(pc.reserve_preview_capacity(reserved))
        data = bytearray(b"M" * 2048)
        token = pc.publish_preview(data, ttl_seconds=60, reserved_bytes=reserved)
        self.assertIsNotNone(token)
        self.assertEqual(len(token), 43)
        acquired = pc.acquire_preview(token)
        self.assertIs(acquired, data)
        # Expire while a response is in progress; it must remain until release.
        with pc._LOCK:
            pc._PREVIEWS[token]["expires_at"] = time.monotonic() - 1
        self.assertIsNone(pc.acquire_preview(token))
        pc.release_preview_lease(token)
        self.assertIsNone(pc.acquire_preview(token))

    def test_reserved_capacity_is_bounded(self):
        self.assertTrue(pc.reserve_preview_capacity(pc.PREVIEW_CACHE_MAX_BYTES))
        self.assertFalse(pc.reserve_preview_capacity(1))
        pc.release_preview_reservation(pc.PREVIEW_CACHE_MAX_BYTES)


if __name__ == "__main__":
    unittest.main()
