"""Versioned PNG least-significant-bit text payload handling."""

from __future__ import annotations

import hashlib
import hmac
import struct
import warnings
from pathlib import Path

from PIL import Image, UnidentifiedImageError

from .errors import CapacityError, InputError, PayloadError

MAGIC = b"SHDW"
FORMAT_VERSION = 1
PAYLOAD_TYPE_TEXT = 1
HEADER = struct.Struct(">4sBBQ32s")
HEADER_SIZE = HEADER.size
MAX_INPUT_BYTES = 256 * 1024 * 1024
MAX_IMAGE_PIXELS = 12_000_000
MAX_PAYLOAD_BYTES = 4 * 1024 * 1024
SUPPORTED_MODES = {"RGB", "RGBA"}


def _open_png(path: Path) -> Image.Image:
    try:
        source = path.open("rb")
    except OSError as exc:
        raise InputError(f"Cannot access input file: {exc}") from exc
    with source:
        try:
            size = source.seek(0, 2)
            source.seek(0)
            if size > MAX_INPUT_BYTES:
                raise InputError(
                    f"Input file exceeds the {MAX_INPUT_BYTES // (1024 * 1024)} MiB limit."
                )
            with warnings.catch_warnings():
                warnings.simplefilter("error", Image.DecompressionBombWarning)
                with Image.open(source) as image:
                    if image.format != "PNG":
                        raise InputError("Input must be a PNG image.")
                    width, height = image.size
                    if width <= 0 or height <= 0 or width * height > MAX_IMAGE_PIXELS:
                        raise InputError(
                            f"Image dimensions exceed the {MAX_IMAGE_PIXELS:,}-pixel safety limit."
                        )
                    image.load()
                    return image.copy()
        except InputError:
            raise
        except (
            UnidentifiedImageError,
            OSError,
            Image.DecompressionBombError,
            Image.DecompressionBombWarning,
        ) as exc:
            raise InputError(f"Invalid or unsafe PNG image: {exc}") from exc


def _normalized_image(image: Image.Image) -> Image.Image:
    if image.mode in SUPPORTED_MODES:
        return image
    return image.convert("RGBA" if "transparency" in image.info else "RGB")


def _capacity_bytes(image: Image.Image) -> int:
    width, height = image.size
    return (width * height * 3) // 8


def _read_lsb_bytes(
    samples: bytes, byte_count: int, channel_count: int, start_bit: int = 0
) -> bytes:
    bit_count = byte_count * 8
    usable_samples = len(samples) - (len(samples) // channel_count if channel_count == 4 else 0)
    if start_bit + bit_count > usable_samples:
        raise PayloadError("Image is too small to contain a complete ShadowHide header.")
    raw_index = 0
    logical_index = 0
    while logical_index < start_bit:
        if channel_count == 4 and raw_index % channel_count == 3:
            raw_index += 1
            continue
        logical_index += 1
        raw_index += 1
    output = bytearray(byte_count)
    for byte_index in range(byte_count):
        value = 0
        for _ in range(8):
            value = (value << 1) | (samples[raw_index] & 1)
            raw_index += 1
            if channel_count == 4 and raw_index % channel_count == 3:
                raw_index += 1
        output[byte_index] = value
    return bytes(output)


def _embed_bits(image: Image.Image, data: bytes) -> Image.Image:
    samples = bytearray(image.tobytes())
    channel_count = len(samples) // (image.width * image.height)
    sample_index = 0
    for value in data:
        for shift in range(7, -1, -1):
            while channel_count == 4 and sample_index % channel_count == 3:
                sample_index += 1
            samples[sample_index] = (samples[sample_index] & 0xFE) | ((value >> shift) & 1)
            sample_index += 1
    return Image.frombytes(image.mode, image.size, bytes(samples))


def _embed_payload(image: Image.Image, payload: bytes) -> Image.Image:
    digest = hashlib.sha256(payload).digest()
    header = HEADER.pack(MAGIC, FORMAT_VERSION, PAYLOAD_TYPE_TEXT, len(payload), digest)
    available = _capacity_bytes(image)
    required = len(header) + len(payload)
    if required > available:
        missing = required - available
        raise CapacityError(
            f"Payload needs {required:,} bytes, but the image holds {available:,}; "
            f"it is short by {missing:,} bytes."
        )
    return _embed_bits(image, header + payload)


def encode_text(input_path: Path, output_path: Path, text: str, force: bool = False) -> int:
    """Encode UTF-8 text into a PNG and return the payload byte count."""
    payload = text.encode("utf-8")
    if len(payload) > MAX_PAYLOAD_BYTES:
        raise InputError(f"Text payload exceeds the {MAX_PAYLOAD_BYTES // (1024 * 1024)} MiB limit.")
    image = _normalized_image(_open_png(input_path))
    encoded = _embed_payload(image, payload)
    _save_png_safely(encoded, input_path, output_path, force)
    return len(payload)


def _save_png_safely(
    image: Image.Image, input_path: Path, output_path: Path, force: bool
) -> None:
    from .paths import save_image_safely

    save_image_safely(image, input_path, output_path, force)


def decode_text(input_path: Path) -> str:
    """Extract and validate a version 1 UTF-8 text payload from a PNG."""
    image = _normalized_image(_open_png(input_path))
    samples = image.tobytes()
    channel_count = len(samples) // (image.width * image.height)
    header_bytes = _read_lsb_bytes(samples, HEADER_SIZE, channel_count)
    magic, version, payload_type, payload_length, digest = HEADER.unpack(header_bytes)
    if magic != MAGIC:
        raise PayloadError("No ShadowHide payload header was found.")
    if version != FORMAT_VERSION:
        raise PayloadError(f"Unsupported ShadowHide payload version: {version}.")
    if payload_type != PAYLOAD_TYPE_TEXT:
        raise PayloadError(f"Unsupported ShadowHide payload type: {payload_type}.")
    if payload_length > MAX_PAYLOAD_BYTES:
        raise PayloadError("Declared payload length exceeds the configured safety limit.")
    required_bytes = HEADER_SIZE + payload_length
    if required_bytes > _capacity_bytes(image):
        raise PayloadError("Payload length in header exceeds the image's available capacity.")
    payload = _read_lsb_bytes(samples, payload_length, channel_count, HEADER_SIZE * 8)
    if not hmac.compare_digest(hashlib.sha256(payload).digest(), digest):
        raise PayloadError("Payload integrity check failed; the image may be damaged or modified.")
    try:
        return payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise PayloadError("Payload is not valid UTF-8 text.") from exc


def inspect_png(path: Path) -> dict[str, object]:
    """Return bounded, factual image information for CLI inspection."""
    image = _open_png(path)
    image = _normalized_image(image)
    stat = path.stat()
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return {
        "path": str(path),
        "format": "PNG",
        "width": image.width,
        "height": image.height,
        "mode": image.mode,
        "file_size_bytes": stat.st_size,
        "lsb_capacity_bytes": max(0, _capacity_bytes(image) - HEADER_SIZE),
        "sha256": digest.hexdigest(),
    }


def png_payload_capacity(path: Path) -> int:
    """Return the maximum user payload size in bytes for a validated PNG."""
    image = _normalized_image(_open_png(path))
    return max(0, _capacity_bytes(image) - HEADER_SIZE)


def has_shadowhide_header(path: Path) -> bool:
    """Check whether the first LSB bytes contain ShadowHide's known magic/version."""
    image = _normalized_image(_open_png(path))
    if _capacity_bytes(image) < HEADER_SIZE:
        return False
    samples = image.tobytes()
    channel_count = len(samples) // (image.width * image.height)
    prefix = _read_lsb_bytes(samples, HEADER_SIZE, channel_count)
    magic, version, _, _, _ = HEADER.unpack(prefix)
    return magic == MAGIC and version == FORMAT_VERSION
