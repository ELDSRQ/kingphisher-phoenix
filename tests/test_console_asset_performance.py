"""Performance and decoding contract for the operator-console brand asset."""

from __future__ import annotations

import struct
import zlib
from pathlib import Path

LOGO = Path("apps/operator-ui/src/console/logo.png")
PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"


def _png_chunks(payload: bytes) -> list[tuple[bytes, bytes]]:
    assert payload.startswith(PNG_SIGNATURE)
    chunks: list[tuple[bytes, bytes]] = []
    offset = len(PNG_SIGNATURE)
    while offset < len(payload):
        length = struct.unpack(">I", payload[offset : offset + 4])[0]
        chunk_type = payload[offset + 4 : offset + 8]
        chunk_data = payload[offset + 8 : offset + 8 + length]
        stored_crc = struct.unpack(">I", payload[offset + 8 + length : offset + 12 + length])[0]
        assert zlib.crc32(chunk_type + chunk_data) & 0xFFFFFFFF == stored_crc
        chunks.append((chunk_type, chunk_data))
        offset += length + 12
    assert offset == len(payload)
    return chunks


def test_console_logo_is_decodable_and_bounded_for_its_rendered_size() -> None:
    payload = LOGO.read_bytes()
    chunks = _png_chunks(payload)
    assert chunks[0][0] == b"IHDR"
    assert chunks[-1][0] == b"IEND"

    width, height, bit_depth, color_type, compression, filtering, interlace = struct.unpack(">IIBBBBB", chunks[0][1])
    assert width == height
    assert 36 * 4 <= width <= 36 * 8
    assert (bit_depth, color_type, compression, filtering, interlace) == (
        8,
        2,  # RGB; the source has no alpha channel.
        0,
        0,
        0,
    )

    # The console renders this image at 36 CSS pixels. Keep enough pixels for
    # high-density/zoomed displays without shipping the original multi-megabyte
    # generation canvas in every console session.
    assert len(payload) <= 150_000

    compressed = b"".join(data for kind, data in chunks if kind == b"IDAT")
    scanlines = zlib.decompress(compressed)
    assert len(scanlines) == height * (1 + width * 3)
    stride = 1 + width * 3
    assert all(scanlines[row * stride] in range(5) for row in range(height))
