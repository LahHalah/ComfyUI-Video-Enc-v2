from __future__ import annotations

import atexit
import gc
import json
import os
import shutil
import subprocess
import threading
import time
import uuid
import secrets
from pathlib import Path
from typing import Optional, Dict, Any, Tuple

import numpy as np
import psutil
import pyzipper
from aiohttp import web
from server import PromptServer
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

import folder_paths

from .security import encrypt_stream, b64u_decode, b64u_encode
from .preview_cache import (
    PREVIEW_STREAM_CHUNK_BYTES, PreviewCaptureReader, acquire_preview,
    publish_preview, release_preview_lease, release_preview_reservation,
    reserve_preview_capacity, revoke_preview, start_preview_cleanup_worker, stop_preview_cleanup_worker,
)

try:
    from huggingface_hub import HfApi
except Exception:
    HfApi = None


NODE_VERSION = "2.0.3"
ZIP_MEMBER_NAME = "payload.enc"
ZIP_MANIFEST_NAME = "manifest.json"
PREVIEW_MIN_VALID_BYTES = 1024


def _preview_cors_headers(request) -> Dict[str, str]:
    origin = request.headers.get("Origin", "")
    allowed_origins = {
        item.strip().rstrip("/")
        for item in os.environ.get("LAHHALAH_PREVIEW_ALLOWED_ORIGINS", "").split(",")
        if item.strip()
    }
    if origin and origin.rstrip("/") in allowed_origins:
        return {"Access-Control-Allow-Origin": origin, "Vary": "Origin"}
    return {}


@PromptServer.instance.routes.get("/lahhalah/preview")
async def lahhalah_safe_preview(request):
    """Stream an expiring RAM-only preview; token is accepted only as a Bearer header."""
    authorization = request.headers.get("Authorization", "")
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer":
        token = ""
    payload = acquire_preview(token)
    if payload is None:
        return web.Response(
            status=404,
            text="Preview not found or expired",
            headers={
                "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
                "Pragma": "no-cache",
                "Referrer-Policy": "no-referrer",
                "X-Content-Type-Options": "nosniff",
                **_preview_cors_headers(request),
            },
        )

    response_headers = {
        "Content-Type": "video/mp4",
        "Content-Length": str(len(payload)),
        "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
        "Pragma": "no-cache",
        "Expires": "0",
        "Referrer-Policy": "no-referrer",
        "X-Content-Type-Options": "nosniff",
        "Cross-Origin-Resource-Policy": "same-origin",
        "Content-Disposition": 'inline; filename="preview.mp4"',
    }
    response_headers.update(_preview_cors_headers(request))
    response = web.StreamResponse(status=200, headers=response_headers)
    try:
        await response.prepare(request)
        for offset in range(0, len(payload), PREVIEW_STREAM_CHUNK_BYTES):
            await response.write(payload[offset:offset + PREVIEW_STREAM_CHUNK_BYTES])
        await response.write_eof()
        return response
    finally:
        release_preview_lease(token)


@PromptServer.instance.routes.options("/lahhalah/preview")
async def lahhalah_safe_preview_options(request):
    """Allow cross-origin preview only for explicitly configured frontend origins."""
    origin = request.headers.get("Origin", "")
    allowed = {
        item.strip().rstrip("/")
        for item in os.environ.get("LAHHALAH_PREVIEW_ALLOWED_ORIGINS", "").split(",")
        if item.strip()
    }
    requested_method = request.headers.get("Access-Control-Request-Method", "GET").upper()
    requested_headers = {
        value.strip().lower()
        for value in request.headers.get("Access-Control-Request-Headers", "").split(",")
        if value.strip()
    }
    if (not origin or origin.rstrip("/") not in allowed
            or requested_method != "GET"
            or not requested_headers.issubset({"authorization"})):
        return web.Response(status=403, text="Preview origin or CORS request is not allowed")
    return web.Response(
        status=204,
        headers={
            **_preview_cors_headers(request),
            "Access-Control-Allow-Methods": "GET, OPTIONS",
            "Access-Control-Allow-Headers": "Authorization",
            "Access-Control-Max-Age": "300",
        },
    )


start_preview_cleanup_worker()
atexit.register(stop_preview_cleanup_worker)


class SecurityError(RuntimeError):
    pass


def _b64u_decode_public_key(value: str) -> bytes:
    raw = b64u_decode(value)
    if len(raw) != 65 or raw[0] != 0x04:
        raise ValueError("frontend_public_key must be an uncompressed P-256 public key in base64url")
    return raw


def wrap_password_for_frontend(password: bytes, frontend_public_key_b64: str, job_id: str) -> Dict[str, Any]:
    """Wrap a generated password to a browser-held P-256 ECDH public key."""
    client_public_bytes = _b64u_decode_public_key(frontend_public_key_b64)
    client_public = ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP256R1(), client_public_bytes
    )
    ephemeral_private = ec.generate_private_key(ec.SECP256R1())
    shared_secret = ephemeral_private.exchange(ec.ECDH(), client_public)
    salt = os.urandom(32)
    info = b"LahHalah.ComfyUI-Video-Enc.V2/password-wrap/" + job_id.encode("ascii")
    wrapping_key = HKDF(
        algorithm=hashes.SHA256(), length=32, salt=salt, info=info
    ).derive(shared_secret)
    nonce = os.urandom(12)
    aad = ("LahHalah.VideoEnc.V2:" + job_id).encode("ascii")
    ciphertext = AESGCM(wrapping_key).encrypt(nonce, password, aad)
    ephemeral_public = ephemeral_private.public_key().public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint,
    )
    return {
        "version": 2,
        "curve": "P-256",
        "kdf": "HKDF-SHA256",
        "cipher": "AES-256-GCM",
        "job_id": job_id,
        "ephemeral_public_key": b64u_encode(ephemeral_public),
        "salt": b64u_encode(salt),
        "nonce": b64u_encode(nonce),
        "ciphertext": b64u_encode(ciphertext),
    }


def _assert_no_active_swap() -> None:
    """Fail closed: plaintext process pages/memfd must not be exposed to active swap."""
    swaps_path = Path("/proc/swaps")
    if not swaps_path.is_file():
        raise SecurityError("Cannot verify Linux swap state; refusing plaintext video processing")
    try:
        lines = swaps_path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError as exc:
        raise SecurityError("Cannot read /proc/swaps; refusing plaintext video processing") from exc
    active_entries = [line for line in lines[1:] if line.strip()]
    if active_entries:
        raise SecurityError(
            "Active swap detected. LahHalah V2 refuses to process plaintext because RAM-backed "
            "pages may be written to swap. Disable swap at the runtime/host level and restart ComfyUI."
        )


def _disable_core_dumps() -> None:
    try:
        import resource
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    except Exception as exc:
        raise SecurityError(f"Cannot disable process core dumps: {exc}") from exc


def _safe_remove(path: Optional[str]) -> None:
    if path:
        try:
            if os.path.exists(path):
                os.remove(path)
        except OSError:
            pass


def _read_stderr(proc: subprocess.Popen, capture: list, max_bytes: int = 65536) -> None:
    try:
        while True:
            data = proc.stderr.read(4096)
            if not data:
                break
            current = sum(len(x) for x in capture)
            if current < max_bytes:
                capture.append(data[: max_bytes - current])
    except Exception:
        pass


def _write_all(stream, data: bytes) -> None:
    """Write every byte; unbuffered pipe writes are allowed to be partial."""
    view = memoryview(data)
    while view:
        written = stream.write(view)
        if written is None or written <= 0:
            raise BrokenPipeError("FFmpeg stdin accepted no more frame bytes")
        view = view[written:]


def _feed_video_frames(proc: subprocess.Popen, images, errors: list) -> None:
    try:
        for index in range(int(images.shape[0])):
            frame = images[index].detach().to("cpu").numpy()
            if frame.ndim != 3:
                raise ValueError(f"Frame {index} has invalid rank")
            if frame.shape[-1] == 4:
                frame = frame[..., :3]
            if frame.shape[-1] != 3:
                raise ValueError(f"Expected RGB/RGBA frames, got {frame.shape[-1]} channels")
            frame_bytes = np.clip(frame * 255.0, 0, 255).astype(np.uint8, copy=False).tobytes()
            _write_all(proc.stdin, frame_bytes)
            del frame_bytes, frame
        proc.stdin.close()
    except BrokenPipeError:
        # FFmpeg may close an input early when -shortest trims the longer stream.
        pass
    except Exception as exc:
        errors.append(exc)
        try:
            proc.stdin.close()
        except Exception:
            pass


def _feed_audio_pipe(write_fd: int, waveform, errors: list) -> None:
    try:
        chunk_samples = 131072
        total = int(waveform.shape[1])
        for start in range(0, total, chunk_samples):
            end = min(start + chunk_samples, total)
            chunk = waveform[:, start:end].transpose(0, 1).contiguous()
            pcm = (chunk.clamp(-1.0, 1.0).numpy() * 32767.0).round().astype(np.int16).tobytes()
            view = memoryview(pcm)
            while view:
                written = os.write(write_fd, view)
                if written <= 0:
                    raise BrokenPipeError("Audio pipe closed")
                view = view[written:]
            del pcm, view, chunk
    except BrokenPipeError:
        # Expected when FFmpeg's -shortest option stops consuming the longer audio input.
        pass
    except Exception as exc:
        errors.append(exc)
    finally:
        try:
            os.close(write_fd)
        except OSError:
            pass


def _prepare_audio(audio) -> Tuple[bool, Any, int, int]:
    if audio is None:
        return False, None, 0, 0
    waveform = audio.get("waveform")
    if waveform is None:
        return False, None, 0, 0
    waveform = waveform[0].detach().to("cpu")
    sample_rate = int(audio.get("sample_rate", 0))
    if waveform.ndim != 2 or waveform.shape[0] < 1 or waveform.shape[1] <= 1:
        raise ValueError("AUDIO waveform has an unsupported shape")
    if sample_rate < 8000 or sample_rate > 192000:
        raise ValueError("AUDIO sample rate is invalid")
    channels = int(waveform.shape[0])
    if channels > 8:
        raise ValueError("AUDIO has too many channels")
    return True, waveform, sample_rate, channels


def _upload_to_hf(path: str, repo_id: str, repo_type: str) -> Tuple[bool, str]:
    if HfApi is None:
        return False, "huggingface_hub is not installed"
    token = os.environ.get("HF_TOKEN", "").strip()
    if not token:
        return False, "HF_TOKEN environment variable is not set"
    if not repo_id or "username/" in repo_id or repo_id == "username/repo_name":
        return False, "Invalid Hugging Face repo_id"
    try:
        HfApi(token=token).upload_file(
            path_or_fileobj=path,
            path_in_repo=f"lahhalah_secure/{os.path.basename(path)}",
            repo_id=repo_id,
            repo_type=repo_type,
        )
        return True, "uploaded"
    except Exception:
        # Do not print exception bodies: HTTP errors may contain request metadata.
        return False, "upload failed; inspect Hugging Face permissions and server logs"


class LahHalahVideoEncryptor:
    @classmethod
    def INPUT_TYPES(cls):
        return {
            "required": {
                "images": ("IMAGE",),
                "frontend_public_key": ("STRING", {
                    "default": "",
                    "multiline": False,
                    "placeholder": "AUTO in ComfyUI UI; external API frontend injects this",
                }),
                "output_mode": (["strict_stream", "compatibility_memfd"], {
                    "default": "strict_stream"
                }),
                "compatibility_ram_limit_mb": ("INT", {"default": 2048, "min": 128, "max": 16384}),
                "preview_in_comfy": ("BOOLEAN", {"default": False, "label": "Safe Preview in ComfyUI (RAM only)"}),
                "preview_max_mb": ("INT", {"default": 128, "min": 16, "max": 256}),
                "preview_ttl_minutes": ("INT", {"default": 15, "min": 1, "max": 60}),
                "fps": ("INT", {"default": 24, "min": 1, "max": 120}),
                "crf": ("INT", {"default": 23, "min": 0, "max": 51}),
                "preset": (["ultrafast", "superfast", "veryfast", "faster", "fast", "medium"],),
                "upload_to_hf": ("BOOLEAN", {"default": False}),
                "hf_repo_id": ("STRING", {"default": "username/repo_name"}),
                "hf_repo_type": (["dataset", "model"], {"default": "dataset"}),
            },
            "optional": {"audio": ("AUDIO",)},
        }

    RETURN_TYPES = ()
    FUNCTION = "encrypt_video"
    OUTPUT_NODE = True
    CATEGORY = "Security/LahHalah"

    def encrypt_video(self, images, frontend_public_key, output_mode="strict_stream",
                      compatibility_ram_limit_mb=2048, preview_in_comfy=False,
                      preview_max_mb=128, preview_ttl_minutes=15,
                      fps=24, crf=23, preset="medium",
                      upload_to_hf=False, hf_repo_id="username/repo_name", hf_repo_type="dataset",
                      audio=None):
        process = None
        feed_thread = None
        audio_thread = None
        stderr_thread = None
        audio_read_fd = None
        audio_write_fd = None
        memfd = None
        partial_path = None
        final_path = None
        created_partial = False
        created_final = False
        feeder_errors = []
        stderr_capture = []
        preview_capture = None
        preview_reserved = False
        preview_reservation_bytes = 0
        preview_status = "disabled"
        preview_url = None
        preview_token = None
        job_id = uuid.uuid4().hex

        try:
            if not isinstance(frontend_public_key, str) or not frontend_public_key.strip():
                raise ValueError(
                    "API security: frontend_public_key is missing. In the normal ComfyUI UI, "
                    "make sure the LahHalah frontend extension is loaded; it generates and "
                    "injects a one-job P-256 key automatically. When calling the ComfyUI API "
                    "from an external frontend, generate a P-256 session and inject its "
                    "base64url public key into this input."
                )
            if not shutil.which("ffmpeg"):
                raise RuntimeError("FFmpeg executable was not found")
            if images.ndim != 4 or images.shape[0] < 1:
                raise ValueError("IMAGE input must have shape [frames, height, width, channels]")
            batch_size, height, width, channels = map(int, images.shape)
            if channels not in (3, 4):
                raise ValueError("IMAGE input must contain RGB or RGBA frames")
            if height < 2 or width < 2:
                raise ValueError("Video dimensions must be at least 2x2")
            if preset not in {"ultrafast", "superfast", "veryfast", "faster", "fast", "medium"}:
                raise ValueError("Unsupported FFmpeg preset")
            if not (1 <= int(fps) <= 120) or not (0 <= int(crf) <= 51):
                raise ValueError("FPS or CRF is outside the supported range")
            if output_mode not in {"strict_stream", "compatibility_memfd"}:
                raise ValueError("Unsupported output mode")
            if not (128 <= int(compatibility_ram_limit_mb) <= 16384):
                raise ValueError("compatibility_ram_limit_mb must be between 128 and 16384")
            if not (16 <= int(preview_max_mb) <= 256):
                raise ValueError("preview_max_mb must be between 16 and 256")
            if not (1 <= int(preview_ttl_minutes) <= 60):
                raise ValueError("preview_ttl_minutes must be between 1 and 60")
            if batch_size > 20000:
                raise ValueError("Frame batch exceeds safety limit")

            _assert_no_active_swap()
            _disable_core_dumps()
            if psutil.virtual_memory().available < 512 * 1024 * 1024:
                raise MemoryError("Available RAM is below 512 MiB; refusing to start secure encoding")

            if preview_in_comfy:
                preview_reservation_bytes = int(preview_max_mb) * 1024 * 1024
                if reserve_preview_capacity(preview_reservation_bytes):
                    preview_reserved = True
                    preview_status = "capturing"
                else:
                    # Preview is optional: keep encryption working, but do not exceed the global RAM budget.
                    preview_status = "memory_budget_full"

            audio_enabled, audio_waveform, audio_sr, audio_channels = _prepare_audio(audio)
            if audio_enabled:
                audio_read_fd, audio_write_fd = os.pipe()
                os.set_inheritable(audio_read_fd, True)

            if output_mode == "compatibility_memfd":
                if not hasattr(os, "memfd_create"):
                    raise SecurityError("compatibility_memfd requires Linux memfd_create; use strict_stream instead")
                memfd = os.memfd_create("lahhalah-video-plaintext", flags=0)
                os.fchmod(memfd, 0o600)
                output_target = f"/proc/self/fd/{memfd}"
            else:
                output_target = "pipe:1"

            # Build FFmpeg arguments explicitly to avoid user-controlled shell parsing.
            even_w = width if width % 2 == 0 else width - 1
            even_h = height if height % 2 == 0 else height - 1
            command = [
                "ffmpeg", "-hide_banner", "-nostdin", "-y", "-loglevel", "error",
                "-f", "rawvideo", "-vcodec", "rawvideo", "-pix_fmt", "rgb24",
                "-s:v", f"{width}x{height}", "-r", str(int(fps)), "-i", "pipe:0",
            ]
            if audio_enabled:
                command += ["-f", "s16le", "-ar", str(audio_sr), "-ac", str(audio_channels), "-i", f"pipe:{audio_read_fd}"]
            command += [
                "-map", "0:v:0", "-c:v", "libx264", "-preset", preset, "-crf", str(int(crf)),
                "-pix_fmt", "yuv420p", "-profile:v", "high", "-tag:v", "avc1",
                "-tune", "zerolatency", "-vf", f"scale={even_w}:{even_h}:flags=lanczos",
            ]
            if audio_enabled:
                command += ["-map", "1:a:0", "-c:a", "aac", "-b:a", "192k", "-ar", "48000", "-ac", "2", "-shortest"]
            else:
                command += ["-an"]
            if output_mode == "strict_stream":
                command += ["-movflags", "+frag_keyframe+empty_moov+default_base_moof", "-frag_duration", "2000000", "-f", "mp4", "pipe:1"]
            else:
                command += ["-movflags", "+faststart", "-f", "mp4", output_target]

            pass_fds = []
            if audio_enabled:
                pass_fds.append(audio_read_fd)
            if memfd is not None:
                pass_fds.append(memfd)

            process = subprocess.Popen(
                command,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE if output_mode == "strict_stream" else subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                bufsize=0,
                close_fds=True,
                pass_fds=tuple(pass_fds),
            )
            if audio_read_fd is not None:
                os.close(audio_read_fd)
                audio_read_fd = None

            feed_thread = threading.Thread(target=_feed_video_frames, args=(process, images, feeder_errors), daemon=True)
            feed_thread.start()
            stderr_thread = threading.Thread(target=_read_stderr, args=(process, stderr_capture), daemon=True)
            stderr_thread.start()
            if audio_enabled:
                audio_thread = threading.Thread(target=_feed_audio_pipe, args=(audio_write_fd, audio_waveform, feeder_errors), daemon=True)
                audio_thread.start()
                audio_write_fd = None  # ownership transferred to audio feeder

            full_output_folder = folder_paths.get_output_directory()
            os.makedirs(full_output_folder, exist_ok=True)
            # Opaque random filename: do not leak workflow/video/user titles in the output path.
            archive_name = f"lahhalah_{job_id[:16]}.zip"
            subfolder = ""
            final_path = os.path.join(full_output_folder, archive_name)
            partial_path = final_path + f".{job_id}.partial"

            password_text = __import__("secrets").token_urlsafe(32)
            password_bytes = password_text.encode("ascii")
            wrapped_secret = wrap_password_for_frontend(password_bytes, frontend_public_key.strip(), job_id)
            del password_text

            archive_fd = os.open(
                partial_path, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600
            )
            created_partial = True
            with os.fdopen(archive_fd, "w+b") as archive_file:
                with pyzipper.AESZipFile(
                    archive_file,
                    "w",
                    compression=pyzipper.ZIP_STORED,
                ) as archive:
                    archive.setpassword(password_bytes)
                    archive.setencryption(pyzipper.WZ_AES, nbits=256)
                    manifest = {
                        "format": "LahHalah Video Enc V2",
                        "version": NODE_VERSION,
                        "payload": ZIP_MEMBER_NAME,
                        "inner_encryption": "XChaCha20-Poly1305 Secretstream",
                        "outer_encryption": "WinZip AES-256",
                        "created_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                        "output_mode": output_mode,
                    }
                    archive.writestr(ZIP_MANIFEST_NAME, json.dumps(manifest, separators=(",", ":")).encode("utf-8"))
                    with archive.open(ZIP_MEMBER_NAME, "w", force_zip64=True) as encrypted_member:
                        if output_mode == "strict_stream":
                            source_for_encryption = process.stdout
                            if preview_reserved:
                                preview_capture = PreviewCaptureReader(
                                    source_for_encryption,
                                    preview_reservation_bytes,
                                    memory_guard=lambda: psutil.virtual_memory().available < 256 * 1024 * 1024,
                                )
                                source_for_encryption = preview_capture
                            encrypt_stream(source_for_encryption, encrypted_member, password_bytes)
                        else:
                            memfd_limit = int(compatibility_ram_limit_mb) * 1024 * 1024
                            while process.poll() is None:
                                current_memfd_size = os.fstat(memfd).st_size
                                if current_memfd_size > memfd_limit:
                                    process.kill()
                                    raise MemoryError(
                                        f"Compatibility MP4 exceeded the configured {compatibility_ram_limit_mb} MiB RAM limit"
                                    )
                                time.sleep(0.05)
                            feed_thread.join()
                            if audio_thread is not None:
                                audio_thread.join()
                            if process.returncode != 0:
                                err = b"".join(stderr_capture).decode("utf-8", "replace")[-4000:]
                                raise RuntimeError(f"FFmpeg failed: {err or 'unknown error'}")
                            if feeder_errors:
                                raise RuntimeError(f"Video/audio feeder failed: {feeder_errors[0]}")
                            os.lseek(memfd, 0, os.SEEK_SET)
                            with os.fdopen(os.dup(memfd), "rb", buffering=0) as source:
                                source_for_encryption = source
                                if preview_reserved:
                                    preview_capture = PreviewCaptureReader(
                                        source,
                                        preview_reservation_bytes,
                                        memory_guard=lambda: psutil.virtual_memory().available < 256 * 1024 * 1024,
                                    )
                                    source_for_encryption = preview_capture
                                encrypt_stream(source_for_encryption, encrypted_member, password_bytes)
                # Persist the already-encrypted archive before publishing its final name.
                archive_file.flush()
                os.fsync(archive_file.fileno())

            if output_mode == "strict_stream":
                feed_thread.join()
                if audio_thread is not None:
                    audio_thread.join()
                process.wait()
                if process.returncode != 0:
                    err = b"".join(stderr_capture).decode("utf-8", "replace")[-4000:]
                    raise RuntimeError(f"FFmpeg failed: {err or 'unknown error'}")
                if feeder_errors:
                    raise RuntimeError(f"Video/audio feeder failed: {feeder_errors[0]}")
            if stderr_thread is not None:
                stderr_thread.join(timeout=2)

            with open(partial_path, "rb") as archive_check:
                if len(archive_check.read(4)) != 4:
                    raise RuntimeError("Encrypted ZIP output is invalid")
            # Hard-link publish is atomic and fails rather than overwriting a pre-existing archive.
            os.link(partial_path, final_path)
            created_final = True
            os.unlink(partial_path)
            created_partial = False
            partial_path = None
            file_size = os.path.getsize(final_path)
            del password_bytes

            # Publish a bounded RAM-only preview only after the encrypted archive is complete.
            if preview_reserved:
                captured_preview = preview_capture.take() if preview_capture is not None else None
                if captured_preview is not None:
                    if (len(captured_preview) >= PREVIEW_MIN_VALID_BYTES
                            and len(captured_preview) >= 8
                            and captured_preview[4:8] == b"ftyp"):
                        token = publish_preview(
                            captured_preview,
                            ttl_seconds=int(preview_ttl_minutes) * 60,
                            reserved_bytes=preview_reservation_bytes,
                        )
                        preview_reserved = False
                        if token:
                            preview_url = "/lahhalah/preview"
                            preview_token = token
                            preview_status = "available"
                        else:
                            preview_status = "memory_budget_full"
                            del captured_preview
                    else:
                        del captured_preview
                        release_preview_reservation(preview_reservation_bytes)
                        preview_reserved = False
                        preview_status = "invalid_or_empty_mp4"
                else:
                    release_preview_reservation(preview_reservation_bytes)
                    preview_reserved = False
                    preview_status = (
                        preview_capture.status if preview_capture is not None
                        else "preview_capture_unavailable"
                    )

            hf_status = "disabled"
            if upload_to_hf:
                uploaded, message = _upload_to_hf(final_path, hf_repo_id, hf_repo_type)
                hf_status = "uploaded" if uploaded else f"failed: {message}"

            output_data = {
                "schema": "lahhalah.video_enc.v2",
                "status": "success",
                "filename": archive_name,
                "subfolder": subfolder,
                "type": "output",
                "size_bytes": file_size,
                "job_id": job_id,
                "output_mode": output_mode,
                "fps": int(fps),
                "frames": batch_size,
                "audio": bool(audio_enabled),
                "zip_encryption": "WinZip AES-256",
                "inner_encryption": "XChaCha20-Poly1305 Secretstream + Argon2id",
                "wrapped_secret": wrapped_secret,
                "upload_status": hf_status,
                "preview_status": preview_status,
                "preview_url": preview_url,
                "preview_token": preview_token,
                "preview_ttl_seconds": int(preview_ttl_minutes) * 60 if preview_url else 0,
            }
            print(f"[LahHalah V2] Encrypted archive created: {archive_name} ({file_size} bytes); plaintext files were not created.")
            return {"ui": {"text": [
                "SECURE VIDEO ENCRYPTION COMPLETE",
                f"Encrypted archive: {archive_name}",
                f"Size: {file_size:,} bytes",
                f"Mode: {output_mode}",
                f"Audio: {'yes' if audio_enabled else 'no'}",
                f"Hugging Face: {hf_status}",
                f"Safe preview: {preview_status}",
                "Password: wrapped for the requesting frontend; not returned in plaintext.",
            ], "secure_video": [output_data]}}

        except Exception as exc:
            if process is not None and process.poll() is None:
                try:
                    process.kill()
                except Exception:
                    pass
            if process is not None:
                try:
                    process.wait(timeout=3)
                except Exception:
                    pass
            if created_partial:
                _safe_remove(partial_path)
            if created_final:
                _safe_remove(final_path)
            if preview_token:
                revoke_preview(preview_token)
                preview_token = None
                preview_url = None
            if preview_capture is not None:
                preview_capture.discard()
            if preview_reserved:
                release_preview_reservation(preview_reservation_bytes)
                preview_reserved = False
            safe_message = str(exc)
            print(f"[LahHalah V2] ERROR: {safe_message}")
            # Propagate the exception so ComfyUI/API marks the prompt as failed.
            # Returning a normal ui payload here would incorrectly look like success.
            raise

        finally:
            if feed_thread is not None and feed_thread.is_alive():
                feed_thread.join(timeout=1)
            if audio_thread is not None and audio_thread.is_alive():
                audio_thread.join(timeout=1)
            if stderr_thread is not None and stderr_thread.is_alive():
                stderr_thread.join(timeout=1)
            if process is not None:
                for stream in (process.stdin, process.stdout, process.stderr):
                    if stream is not None:
                        try:
                            stream.close()
                        except Exception:
                            pass
            if audio_write_fd is not None:
                try:
                    os.close(audio_write_fd)
                except OSError:
                    pass
            if audio_read_fd is not None:
                try:
                    os.close(audio_read_fd)
                except OSError:
                    pass
            if memfd is not None:
                try:
                    os.close(memfd)
                except OSError:
                    pass
            if preview_capture is not None and preview_url is None:
                preview_capture.discard()
            if preview_reserved:
                release_preview_reservation(preview_reservation_bytes)
                preview_reserved = False
            gc.collect()


NODE_CLASS_MAPPINGS = {
    "LahHalahVideoEncryptor": LahHalahVideoEncryptor,
}

NODE_DISPLAY_NAME_MAPPINGS = {
    "LahHalahVideoEncryptor": "🛡️ LahHalah Video Encryptor V2.0.3 (Auto-Key + API)",
}

WEB_DIRECTORY = "./web"
__all__ = ["NODE_CLASS_MAPPINGS", "NODE_DISPLAY_NAME_MAPPINGS", "WEB_DIRECTORY"]
