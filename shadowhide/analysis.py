"""Cautious, ShadowHide-specific image analysis reports."""

from __future__ import annotations

import math
import struct
from datetime import datetime, timezone
from itertools import islice
from pathlib import Path
from typing import TypeAlias

from PIL import ExifTags, Image

from . import __version__
from .core import (
    MAX_INPUT_BYTES,
    _has_shadowhide_header,
    _inspect_png,
)
from .errors import InputError

JsonValue: TypeAlias = None | bool | int | float | str | list["JsonValue"] | dict[str, "JsonValue"]
MAX_METADATA_ITEMS = 25
MAX_METADATA_TEXT_LENGTH = 500
MAX_LSB_SAMPLE_PIXELS = 100_000
PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"


def _png_chunk_summary(path: Path) -> dict[str, object]:
    try:
        file_size = path.stat().st_size
        if file_size > MAX_INPUT_BYTES:
            raise InputError("PNG exceeds the configured input size limit.")
        with path.open("rb") as source:
            if source.read(len(PNG_SIGNATURE)) != PNG_SIGNATURE:
                return {"status": "invalid", "present": False, "bytes": 0}

            while True:
                chunk_header = source.read(8)
                if len(chunk_header) != 8:
                    return {
                        "status": "incomplete",
                        "present": False,
                        "bytes": 0,
                        "details": "PNG ended before an IEND chunk was found.",
                    }

                chunk_length, chunk_type = struct.unpack(">I4s", chunk_header)
                chunk_end = source.tell() + chunk_length + 4
                if chunk_end > file_size:
                    return {
                        "status": "incomplete",
                        "present": False,
                        "bytes": 0,
                        "details": "PNG chunk extends beyond the end of the file.",
                    }
                source.seek(chunk_length, 1)
                if len(source.read(4)) != 4:
                    return {
                        "status": "incomplete",
                        "present": False,
                        "bytes": 0,
                        "details": "PNG chunk is missing its CRC.",
                    }

                if chunk_type == b"IEND":
                    if chunk_length != 0:
                        return {
                            "status": "malformed",
                            "present": False,
                            "bytes": 0,
                            "details": "PNG IEND chunk has an invalid length.",
                        }
                    trailing_bytes = file_size - source.tell()
                    return {
                        "status": "found" if trailing_bytes else "not_found",
                        "present": trailing_bytes > 0,
                        "bytes": trailing_bytes,
                        "details": (
                            "Trailing bytes after the PNG IEND chunk were found."
                            if trailing_bytes
                            else "No trailing bytes after IEND were detected."
                        ),
                    }
    except OSError as exc:
        raise InputError(f"Cannot inspect PNG chunks: {exc}") from exc


def _json_safe(value: object, depth: int = 0) -> JsonValue:
    if value is None or isinstance(value, (bool, int)):
        return value
    if isinstance(value, float):
        return value if math.isfinite(value) else str(value)
    if isinstance(value, str):
        return value[:MAX_METADATA_TEXT_LENGTH]
    if isinstance(value, bytes):
        return {
            "hex_prefix": value[:64].hex(),
            "length": len(value),
            "truncated": len(value) > 64,
        }
    if depth >= 3:
        return str(value)[:MAX_METADATA_TEXT_LENGTH]
    if isinstance(value, (tuple, list)):
        return [_json_safe(item, depth + 1) for item in islice(value, 10)]
    if isinstance(value, dict):
        return {
            str(key)[:100]: _json_safe(item, depth + 1) for key, item in islice(value.items(), 10)
        }
    return str(value)[:MAX_METADATA_TEXT_LENGTH]


def _metadata_summary(image: Image.Image) -> dict[str, object]:
    try:
        exif = image.getexif()
        exif_tags = [
            {
                "tag": tag,
                "name": ExifTags.TAGS.get(tag, f"0x{tag:04x}"),
                "value": _json_safe(value),
            }
            for tag, value in islice(exif.items(), MAX_METADATA_ITEMS)
        ]
        info_items = islice(
            (item for item in image.info.items() if item[0] not in {"icc_profile", "exif"}),
            MAX_METADATA_ITEMS,
        )
        png_info = [
            {"key": str(key)[:100], "value": _json_safe(value)} for key, value in info_items
        ]
        return {
            "status": "available",
            "count": len(exif),
            "tags": exif_tags,
            "png_info": png_info,
        }
    except (OSError, ValueError, SyntaxError) as exc:
        return {"status": "error", "error": str(exc)[:MAX_METADATA_TEXT_LENGTH]}


def _channel_lsb_balance(image: Image.Image) -> tuple[dict[str, float], int]:
    try:
        rgb = image.convert("RGB")
        samples = rgb.tobytes()
        pixel_count = rgb.width * rgb.height
        sample_count = min(pixel_count, MAX_LSB_SAMPLE_PIXELS)
        odd_bits = [0, 0, 0]

        for sample_number in range(sample_count):
            pixel_index = sample_number * pixel_count // sample_count
            offset = pixel_index * 3
            odd_bits[0] += samples[offset] & 1
            odd_bits[1] += samples[offset + 1] & 1
            odd_bits[2] += samples[offset + 2] & 1

        return (
            {
                "red": round(odd_bits[0] / sample_count, 4),
                "green": round(odd_bits[1] / sample_count, 4),
                "blue": round(odd_bits[2] / sample_count, 4),
            },
            sample_count,
        )
    except (OSError, ValueError, SyntaxError) as exc:
        raise InputError(f"Cannot calculate PNG channel statistics: {exc}") from exc


def analyze_png(path: Path) -> dict[str, object]:
    """Create an evidence-oriented report with explicit scope and limitations."""
    image, image_facts = _inspect_png(path)
    header_found = _has_shadowhide_header(image)
    appended = _png_chunk_summary(path)
    metadata = _metadata_summary(image)
    lsb_balance, sampled_pixels = _channel_lsb_balance(image)
    return {
        "tool": "ShadowHide",
        "version": __version__,
        "analyzed_at": datetime.now(timezone.utc).isoformat(),
        "input": image_facts,
        "methods": [
            "PNG validation",
            "file size and dimensions",
            "SHA-256",
            "ShadowHide v1 header check",
            "EXIF and PNG metadata summary",
            "PNG trailing-data scan",
            "bounded channel LSB balance sample",
        ],
        "observations": [
            {
                "kind": "shadowhide_header",
                "status": "recognized" if header_found else "not_recognized",
                "confidence": "confirmed" if header_found else "none",
            }
        ],
        "forensics": {
            "appended_data": appended,
            "metadata": metadata,
            "channel_lsb_balance": lsb_balance,
            "channel_lsb_sampled_pixels": sampled_pixels,
        },
        "limitations": [
            "This check only recognizes ShadowHide version 1 headers.",
            "A missing header does not show that an image is free of hidden data.",
            "Trailing data and metadata can be legitimate or benign, and are not proof of malicious content.",
            "LSB balance is only a coarse statistical signal and should not be treated as evidence.",
            "This is not malware scanning or a verdict that the file is safe.",
        ],
    }
