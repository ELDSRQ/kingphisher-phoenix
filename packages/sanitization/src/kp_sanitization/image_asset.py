"""Dependency-free inspection of reusable raster image assets.

The asset library stores operator-vetted images (FLUX-generated banners, brand
logos) that are later inlined into template ``safe_html`` as ``data:image``
URIs. Those inline URIs are already gated by the sanitizer and SafetyValidator,
which accept ONLY raster types ``png/jpeg/gif/webp`` (SVG is excluded because it
can carry script). This module enforces the SAME allow-list at the point bytes
enter the store, by sniffing magic bytes — so a non-raster payload (SVG, HTML,
a script with an image extension) is rejected on upload, before it can ever be
embedded. Parsed dimensions are also bounded (KP-AUD-013): an asset whose
declared geometry exceeds the per-side or total-pixel ceiling is rejected, in
addition to the raw byte ceiling, because declared geometry is independent of
the compressed byte size (a tiny payload can still declare an enormous canvas —
a decompression bomb). When a header cannot be parsed the dimensions are 0
(best-effort, as before) and the bound does not fire; the magic-byte and
byte-size gates still apply.

No third-party dependency (notably not Pillow): the header formats needed for
the four permitted raster types are small and stable, and avoiding an image
library keeps the attack surface of the upload path minimal.
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass

#: The only media types that may enter the asset store — identical to the raster
#: set the sanitizer/validator permit for inline ``data:image`` URIs.
ALLOWED_MEDIA_TYPES: frozenset[str] = frozenset({"image/png", "image/jpeg", "image/gif", "image/webp"})

#: Hard ceiling on a single stored asset's raw byte size. An applied banner is
#: base64-inlined into ``safe_html`` (~4/3 expansion) and must still leave room
#: under the body caps (generation 200k, logo 400k), so assets are kept small;
#: callers should pass web-optimized images (≈600px banners).
MAX_ASSET_BYTES = 512_000

#: Hard ceiling on a stored asset's declared geometry (KP-AUD-013), enforced in
#: addition to :data:`MAX_ASSET_BYTES`. A real web-optimized banner or logo is
#: at most a few thousand pixels per side, so a larger declared dimension is a
#: mistake or a decompression bomb. ``MAX_ASSET_DIMENSION`` bounds either side;
#: ``MAX_ASSET_PIXELS`` bounds the total area (width * height) so a decoder's
#: memory is bounded even when neither side alone is extreme.
MAX_ASSET_DIMENSION = 8192
MAX_ASSET_PIXELS = 4096 * 4096  # 16,777,216 px (~16.7 megapixels)


class ImageAssetError(ValueError):
    """A stable, non-secret reason an uploaded asset is not an accepted raster image."""


@dataclass(frozen=True, slots=True)
class ImageAssetInfo:
    """Validated facts about an accepted raster image."""

    media_type: str
    width: int
    height: int
    byte_size: int
    sha256: str


def inspect_raster_image(data: bytes) -> ImageAssetInfo:
    """Validate ``data`` is an accepted raster image and return its facts.

    Raises :class:`ImageAssetError` for an empty payload, one over
    :data:`MAX_ASSET_BYTES`, anything whose magic bytes are not one of the four
    permitted raster formats (this is what rejects SVG and non-images), or an
    asset whose parsed dimensions exceed :data:`MAX_ASSET_DIMENSION` per side or
    :data:`MAX_ASSET_PIXELS` in total. Width/height remain best-effort: ``0``
    when the header cannot be parsed, which never blocks an otherwise-valid
    raster (the dimension bound then does not fire).
    """

    if not data:
        raise ImageAssetError("empty image payload")
    if len(data) > MAX_ASSET_BYTES:
        raise ImageAssetError(
            f"image is {len(data)} bytes; the limit is {MAX_ASSET_BYTES} bytes (use a web-optimized asset)"
        )

    media_type = _sniff_media_type(data)
    if media_type is None:
        raise ImageAssetError(
            "unsupported image: only png, jpeg, gif and webp raster images are accepted (svg is not permitted)"
        )

    width, height = _dimensions(media_type, data)
    # Dimension bound (KP-AUD-013), in addition to the byte ceiling above. A
    # tiny compressed payload can still declare an enormous canvas (a
    # decompression bomb), so reject oversized declared geometry. Unparsed
    # headers yield 0 and fall through, preserving the best-effort contract.
    if width > MAX_ASSET_DIMENSION or height > MAX_ASSET_DIMENSION:
        raise ImageAssetError(
            f"image dimensions {width}x{height} exceed the {MAX_ASSET_DIMENSION}px per-side limit "
            "(use a web-optimized asset)"
        )
    if width * height > MAX_ASSET_PIXELS:
        raise ImageAssetError(
            f"image has {width * height} pixels; the limit is {MAX_ASSET_PIXELS} pixels (use a web-optimized asset)"
        )
    return ImageAssetInfo(
        media_type=media_type,
        width=width,
        height=height,
        byte_size=len(data),
        sha256=hashlib.sha256(data).hexdigest(),
    )


def _sniff_media_type(data: bytes) -> str | None:
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png"
    if data.startswith(b"\xff\xd8\xff"):
        return "image/jpeg"
    if data[:6] in (b"GIF87a", b"GIF89a"):
        return "image/gif"
    if len(data) >= 12 and data[0:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "image/webp"
    return None


def _dimensions(media_type: str, data: bytes) -> tuple[int, int]:
    try:
        if media_type == "image/png":
            # IHDR is the first chunk: width/height are 32-bit big-endian at 16..24.
            if len(data) >= 24 and data[12:16] == b"IHDR":
                w, h = struct.unpack(">II", data[16:24])
                return int(w), int(h)
        elif media_type == "image/gif":
            w, h = struct.unpack("<HH", data[6:10])
            return int(w), int(h)
        elif media_type == "image/jpeg":
            return _jpeg_dimensions(data)
        elif media_type == "image/webp":
            return _webp_dimensions(data)
    except (struct.error, IndexError, ValueError):
        return (0, 0)
    return (0, 0)


def _jpeg_dimensions(data: bytes) -> tuple[int, int]:
    # Walk the marker segments until a Start-Of-Frame carries the dimensions.
    i = 2
    n = len(data)
    while i + 9 < n:
        if data[i] != 0xFF:
            i += 1
            continue
        marker = data[i + 1]
        # Standalone markers (no length payload): padding and RSTn.
        if marker in (0xD8, 0xD9) or 0xD0 <= marker <= 0xD7:
            i += 2
            continue
        seg_len = struct.unpack(">H", data[i + 2 : i + 4])[0]
        # SOF0..SOF15 carry frame geometry, excluding DHT(C4)/JPG(C8)/DAC(CC).
        if 0xC0 <= marker <= 0xCF and marker not in (0xC4, 0xC8, 0xCC):
            height, width = struct.unpack(">HH", data[i + 5 : i + 9])
            return int(width), int(height)
        i += 2 + seg_len
    return (0, 0)


def _webp_dimensions(data: bytes) -> tuple[int, int]:
    fmt = data[12:16]
    if fmt == b"VP8 " and len(data) >= 30:
        w = struct.unpack("<H", data[26:28])[0] & 0x3FFF
        h = struct.unpack("<H", data[28:30])[0] & 0x3FFF
        return int(w), int(h)
    if fmt == b"VP8L" and len(data) >= 25 and data[20] == 0x2F:
        b0, b1, b2, b3 = data[21], data[22], data[23], data[24]
        w = (((b1 & 0x3F) << 8) | b0) + 1
        h = (((b3 & 0x0F) << 10) | (b2 << 2) | ((b1 & 0xC0) >> 6)) + 1
        return int(w), int(h)
    if fmt == b"VP8X" and len(data) >= 30:
        w = (data[24] | (data[25] << 8) | (data[26] << 16)) + 1
        h = (data[27] | (data[28] << 8) | (data[29] << 16)) + 1
        return int(w), int(h)
    return (0, 0)
