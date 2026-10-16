"""Tests for the dependency-free raster asset inspector."""

from __future__ import annotations

import struct
import zlib

import pytest
from kp_sanitization.image_asset import (
    MAX_ASSET_BYTES,
    ImageAssetError,
    inspect_raster_image,
)


def _png(width: int, height: int) -> bytes:
    def chunk(tag: bytes, data: bytes) -> bytes:
        return struct.pack(">I", len(data)) + tag + data + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)

    ihdr = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    idat = zlib.compress((b"\x00" + b"\xff\xff\xff" * width) * height)
    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr) + chunk(b"IDAT", idat) + chunk(b"IEND", b"")


def _gif(width: int, height: int) -> bytes:
    return b"GIF89a" + struct.pack("<HH", width, height) + b"\x00" * 16


def _jpeg(width: int, height: int) -> bytes:
    # SOI + a minimal SOF0 carrying the geometry + EOI.
    sof = b"\xff\xc0" + struct.pack(">H", 17) + b"\x08" + struct.pack(">HH", height, width) + b"\x03" + b"\x00" * 9
    return b"\xff\xd8" + sof + b"\xff\xd9"


def _webp_vp8x(width: int, height: int) -> bytes:
    body = b"VP8X" + struct.pack("<I", 10) + b"\x00" * 4
    body += struct.pack("<I", width - 1)[:3] + struct.pack("<I", height - 1)[:3]
    return b"RIFF" + struct.pack("<I", len(body) + 4) + b"WEBP" + body


def test_accepts_png_and_parses_dimensions() -> None:
    info = inspect_raster_image(_png(600, 188))
    assert info.media_type == "image/png"
    assert (info.width, info.height) == (600, 188)
    assert info.byte_size > 0
    assert len(info.sha256) == 64


def test_accepts_gif_jpeg_webp_dimensions() -> None:
    assert inspect_raster_image(_gif(7, 3)).width == 7
    j = inspect_raster_image(_jpeg(320, 100))
    assert (j.media_type, j.width, j.height) == ("image/jpeg", 320, 100)
    w = inspect_raster_image(_webp_vp8x(1024, 320))
    assert (w.media_type, w.width, w.height) == ("image/webp", 1024, 320)


def test_sha256_is_stable_and_content_addressed() -> None:
    data = _png(10, 10)
    assert inspect_raster_image(data).sha256 == inspect_raster_image(data).sha256
    assert inspect_raster_image(_png(10, 10)).sha256 != inspect_raster_image(_png(11, 11)).sha256


def test_rejects_svg() -> None:
    with pytest.raises(ImageAssetError):
        inspect_raster_image(b'<svg xmlns="http://www.w3.org/2000/svg"><script>1</script></svg>')


def test_rejects_non_image_and_empty() -> None:
    with pytest.raises(ImageAssetError):
        inspect_raster_image(b"")
    with pytest.raises(ImageAssetError):
        inspect_raster_image(b"not an image at all")
    with pytest.raises(ImageAssetError):
        inspect_raster_image(b"%PDF-1.7\n...")


def test_rejects_oversize() -> None:
    with pytest.raises(ImageAssetError):
        inspect_raster_image(b"\x89PNG\r\n\x1a\n" + b"\x00" * (MAX_ASSET_BYTES + 1))
