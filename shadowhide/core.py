"""Versioned PNG least-significant-bit payload handling."""

from __future__ import annotations

import hashlib
import hmac
import secrets
import struct
import warnings
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from PIL import Image, UnidentifiedImageError

from .errors import CapacityError, InputError, PayloadError

MAGIC = b"SHDW"
FORMAT_VERSION = 1
PAYLOAD_TYPE_TEXT = 1
PAYLOAD_TYPE_BINARY = 2
PAYLOAD_TYPE_ENCRYPTED = 3
HEADER = struct.Struct(">4sBBQ32s")
HEADER_SIZE = HEADER.size
MAX_INPUT_BYTES = 256 * 1024 * 1024
MAX_IMAGE_PIXELS = 12_000_000
MAX_PAYLOAD_BYTES = 4 * 1024 * 1024
MAX_PASSWORD_BYTES = 1024
SUPPORTED_MODES = {"RGB", "RGBA"}
KDF_ITERATIONS = 600_000
ENCRYPTED_ENVELOPE = struct.Struct(">BBI16s12s")
ENCRYPTED_ENVELOPE_VERSION = 1
AES_GCM_TAG_BYTES = 16

_PAYLOAD_TYPES = {PAYLOAD_TYPE_TEXT, PAYLOAD_TYPE_BINARY, PAYLOAD_TYPE_ENCRYPTED}
MAX_ENCRYPTED_PAYLOAD_BYTES = MAX_PAYLOAD_BYTES + ENCRYPTED_ENVELOPE.size + AES_GCM_TAG_BYTES


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
    if image.mode in {"LA", "PA", "RGBa", "La"}:
        return image.convert("RGBA")
    if image.mode == "P" and "transparency" in image.info:
        return image.convert("RGBA")
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


def _derive_key(password: str, salt: bytes) -> bytes:
    try:
        encoded_password = password.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise InputError("Password must be valid UTF-8 text.") from exc
    if len(encoded_password) > MAX_PASSWORD_BYTES:
        raise InputError(f"Password exceeds the {MAX_PASSWORD_BYTES}-byte limit.")
    return hashlib.pbkdf2_hmac("sha256", encoded_password, salt, KDF_ITERATIONS, dklen=32)


def _encrypt_payload(data: bytes, password: str, original_type: int) -> bytes:
    if not password:
        raise InputError("A non-empty password is required to encrypt a payload.")
    salt = secrets.token_bytes(16)
    nonce = secrets.token_bytes(12)
    envelope = ENCRYPTED_ENVELOPE.pack(
        ENCRYPTED_ENVELOPE_VERSION, original_type, KDF_ITERATIONS, salt, nonce
    )
    key = _derive_key(password, salt)
    encrypted = AESGCM(key).encrypt(nonce, data, envelope)
    return envelope + encrypted


def _decrypt_payload(data: bytes, password: str) -> tuple[int, bytes]:
    if len(data) < ENCRYPTED_ENVELOPE.size + AES_GCM_TAG_BYTES:
        raise PayloadError("Encrypted payload is too short to be valid.")
    envelope = data[: ENCRYPTED_ENVELOPE.size]
    envelope_version, original_type, iterations, salt, nonce = ENCRYPTED_ENVELOPE.unpack(envelope)
    if envelope_version != ENCRYPTED_ENVELOPE_VERSION:
        raise PayloadError(f"Unsupported encrypted payload envelope version: {envelope_version}.")
    try:
        if iterations != KDF_ITERATIONS:
            raise PayloadError("Encrypted payload uses unsupported key-derivation parameters.")
        key = _derive_key(password, salt)
        plaintext = AESGCM(key).decrypt(nonce, data[ENCRYPTED_ENVELOPE.size :], envelope)
    except InvalidTag as exc:
        raise PayloadError(
            "Decryption failed; the password is wrong or the payload was modified."
        ) from exc
    if original_type not in {PAYLOAD_TYPE_TEXT, PAYLOAD_TYPE_BINARY}:
        raise PayloadError(f"Unsupported encrypted payload type: {original_type}.")
    return original_type, plaintext


def _embed_payload(image: Image.Image, payload: bytes, payload_type: int) -> Image.Image:
    if payload_type not in _PAYLOAD_TYPES:
        raise InputError(f"Unsupported payload type: {payload_type}.")
    digest = hashlib.sha256(payload).digest()
    header = HEADER.pack(MAGIC, FORMAT_VERSION, payload_type, len(payload), digest)
    _ensure_capacity(image, len(header) + len(payload))
    return _embed_bits(image, header + payload)


def _ensure_capacity(image: Image.Image, required_bytes: int) -> None:
    available = _capacity_bytes(image)
    if required_bytes > available:
        missing = required_bytes - available
        raise CapacityError(
            f"Payload needs {required_bytes:,} bytes, but the image holds {available:,}; "
            f"it is short by {missing:,} bytes."
        )


def encode_data(
    input_path: Path,
    output_path: Path,
    data: bytes,
    payload_type: int = PAYLOAD_TYPE_TEXT,
    force: bool = False,
    password: str | None = None,
) -> int:
    """Encode a payload of bytes into a PNG and return the payload byte count."""
    if payload_type not in {PAYLOAD_TYPE_TEXT, PAYLOAD_TYPE_BINARY}:
        raise InputError(f"Unsupported payload type: {payload_type}.")
    if len(data) > MAX_PAYLOAD_BYTES:
        size_unit = MAX_PAYLOAD_BYTES // (1024 * 1024)
        raise InputError(f"Payload exceeds the {size_unit} MiB limit.")
    from .paths import validate_output_path

    validate_output_path(input_path, output_path, force)
    original_length = len(data)
    image = _normalized_image(_open_png(input_path))
    if password is not None:
        original_type = payload_type
        payload_type = PAYLOAD_TYPE_ENCRYPTED
        _ensure_capacity(
            image,
            HEADER_SIZE + len(data) + ENCRYPTED_ENVELOPE.size + AES_GCM_TAG_BYTES,
        )
        data = _encrypt_payload(data, password, original_type)
    encoded = _embed_payload(image, data, payload_type)
    _save_png_safely(encoded, input_path, output_path, force)
    return original_length


def encode_text(
    input_path: Path,
    output_path: Path,
    text: str,
    force: bool = False,
    password: str | None = None,
) -> int:
    """Encode UTF-8 text into a PNG and return the payload byte count."""
    payload = text.encode("utf-8")
    return encode_data(input_path, output_path, payload, PAYLOAD_TYPE_TEXT, force, password)


def encode_bytes(
    input_path: Path,
    output_path: Path,
    data: bytes,
    force: bool = False,
    password: str | None = None,
) -> int:
    """Encode raw bytes into a PNG and return the payload byte count."""
    return encode_data(input_path, output_path, data, PAYLOAD_TYPE_BINARY, force, password)


def encode_file(
    input_path: Path,
    output_path: Path,
    file_path: Path,
    force: bool = False,
    password: str | None = None,
) -> int:
    """Encode a file's raw bytes into a PNG and return the file size in bytes."""
    try:
        with file_path.open("rb") as source:
            payload = source.read(MAX_PAYLOAD_BYTES + 1)
    except OSError as exc:
        raise InputError(f"Cannot read payload file: {exc}") from exc
    if len(payload) > MAX_PAYLOAD_BYTES:
        raise InputError(f"Payload exceeds the {MAX_PAYLOAD_BYTES // (1024 * 1024)} MiB limit.")
    return encode_bytes(input_path, output_path, payload, force, password)


def _save_png_safely(image: Image.Image, input_path: Path, output_path: Path, force: bool) -> None:
    from .paths import save_image_safely

    save_image_safely(image, input_path, output_path, force)


def decode_data(input_path: Path, password: str | None = None) -> tuple[int, bytes]:
    """Extract a ShadowHide payload and return its type and payload bytes."""
    image = _normalized_image(_open_png(input_path))
    samples = image.tobytes()
    channel_count = len(samples) // (image.width * image.height)
    header_bytes = _read_lsb_bytes(samples, HEADER_SIZE, channel_count)
    magic, version, payload_type, payload_length, digest = HEADER.unpack(header_bytes)
    if magic != MAGIC:
        raise PayloadError("No ShadowHide payload header was found.")
    if version != FORMAT_VERSION:
        raise PayloadError(f"Unsupported ShadowHide payload version: {version}.")
    if payload_type not in _PAYLOAD_TYPES:
        raise PayloadError(f"Unsupported ShadowHide payload type: {payload_type}.")
    payload_limit = (
        MAX_ENCRYPTED_PAYLOAD_BYTES if payload_type == PAYLOAD_TYPE_ENCRYPTED else MAX_PAYLOAD_BYTES
    )
    if payload_length > payload_limit:
        raise PayloadError("Declared payload length exceeds the configured safety limit.")
    required_bytes = HEADER_SIZE + payload_length
    if required_bytes > _capacity_bytes(image):
        raise PayloadError("Payload length in header exceeds the image's available capacity.")
    payload = _read_lsb_bytes(samples, payload_length, channel_count, HEADER_SIZE * 8)
    if not hmac.compare_digest(hashlib.sha256(payload).digest(), digest):
        raise PayloadError("Payload integrity check failed; the image may be damaged or modified.")
    if payload_type == PAYLOAD_TYPE_ENCRYPTED:
        if password is None:
            raise PayloadError("Password required to decode an encrypted payload.")
        original_type, plaintext = _decrypt_payload(payload, password)
        if len(plaintext) > MAX_PAYLOAD_BYTES:
            raise PayloadError("Decrypted payload exceeds the configured safety limit.")
        return original_type, plaintext
    return payload_type, payload


def decode_text(input_path: Path, password: str | None = None) -> str:
    """Extract and validate a version 1 UTF-8 text payload from a PNG."""
    payload_type, payload = decode_data(input_path, password)
    if payload_type != PAYLOAD_TYPE_TEXT:
        raise PayloadError("Payload is binary data, not a UTF-8 text payload.")
    try:
        return payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise PayloadError("Payload is not valid UTF-8 text.") from exc


def decode_bytes(input_path: Path, password: str | None = None) -> bytes:
    """Extract raw payload bytes from a PNG, regardless of payload type."""
    _, payload = decode_data(input_path, password)
    return payload


def decode_file(
    input_path: Path,
    output_path: Path,
    force: bool = False,
    password: str | None = None,
) -> int:
    """Extract the raw payload bytes and write them to a file."""
    from .paths import validate_output_path, write_bytes_safely

    validate_output_path(input_path, output_path, force)
    payload = decode_bytes(input_path, password)
    write_bytes_safely(payload, input_path, output_path, force)
    return len(payload)


def _inspect_png(path: Path) -> tuple[Image.Image, dict[str, object]]:
    image = _open_png(path)
    image = _normalized_image(image)
    try:
        stat = path.stat()
        digest = hashlib.sha256()
        with path.open("rb") as source:
            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as exc:
        raise InputError(f"Cannot inspect input file: {exc}") from exc
    return image, {
        "path": str(path),
        "format": "PNG",
        "width": image.width,
        "height": image.height,
        "mode": image.mode,
        "file_size_bytes": stat.st_size,
        "lsb_capacity_bytes": max(0, _capacity_bytes(image) - HEADER_SIZE),
        "sha256": digest.hexdigest(),
    }


def inspect_png(path: Path) -> dict[str, object]:
    """Return bounded, factual image information for CLI inspection."""
    _, facts = _inspect_png(path)
    return facts


def png_payload_capacity(path: Path) -> int:
    """Return the maximum user payload size in bytes for a validated PNG."""
    image = _normalized_image(_open_png(path))
    return max(0, _capacity_bytes(image) - HEADER_SIZE)


def has_shadowhide_header(path: Path) -> bool:
    """Check whether the first LSB bytes contain ShadowHide's known magic/version."""
    image = _normalized_image(_open_png(path))
    return _has_shadowhide_header(image)


def _has_shadowhide_header(image: Image.Image) -> bool:
    if _capacity_bytes(image) < HEADER_SIZE:
        return False
    samples = image.tobytes()
    channel_count = len(samples) // (image.width * image.height)
    prefix = _read_lsb_bytes(samples, HEADER_SIZE, channel_count)
    magic, version, _, _, _ = HEADER.unpack(prefix)
    return magic == MAGIC and version == FORMAT_VERSION
