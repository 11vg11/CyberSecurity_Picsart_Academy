from pathlib import Path

import pytest
from PIL import Image

from shadowhide.core import (
    MAX_PAYLOAD_BYTES,
    _decrypt_payload,
    _encrypt_payload,
    _normalized_image,
    decode_bytes,
    decode_text,
    encode_bytes,
    encode_file,
    encode_text,
)
from shadowhide.errors import CapacityError, InputError, OutputError, PayloadError


def make_png(path: Path, size: tuple[int, int] = (64, 64), mode: str = "RGB") -> Path:
    Image.new(mode, size, color=(124, 87, 201) if mode == "RGB" else (124, 87, 201, 180)).save(path)
    return path


@pytest.mark.parametrize(
    "text",
    ["", "hello", "Unicode: привет, こんにちは, 🌍", "line one\nline two"],
)
def test_text_round_trip(tmp_path: Path, text: str) -> None:
    source = make_png(tmp_path / "cover.png")
    output = tmp_path / "encoded.png"
    original = source.read_bytes()

    assert encode_text(source, output, text) == len(text.encode("utf-8"))
    assert decode_text(output) == text
    assert source.read_bytes() == original


def test_rgba_round_trip_preserves_alpha(tmp_path: Path) -> None:
    source = make_png(tmp_path / "cover.png", mode="RGBA")
    output = tmp_path / "encoded.png"

    encode_text(source, output, "alpha")
    with Image.open(source) as before, Image.open(output) as after:
        assert before.getchannel("A").tobytes() == after.getchannel("A").tobytes()
    assert decode_text(output) == "alpha"


def test_grayscale_alpha_round_trip_preserves_alpha(tmp_path: Path) -> None:
    source = tmp_path / "cover-la.png"
    Image.new("LA", (64, 64), color=(200, 180)).save(source)
    output = tmp_path / "encoded.png"

    encode_text(source, output, "alpha")
    with Image.open(source) as before, Image.open(output) as after:
        assert before.getchannel("A").tobytes() == after.getchannel("A").tobytes()
    assert decode_text(output) == "alpha"


def test_lab_image_does_not_get_mistaken_for_alpha() -> None:
    lab_image = Image.new("LAB", (4, 4), color=(100, 120, 140))

    assert _normalized_image(lab_image).mode == "RGB"


def test_binary_round_trip(tmp_path: Path) -> None:
    source = make_png(tmp_path / "cover.png")
    output = tmp_path / "encoded.bin.png"
    payload = b"\x00\x01\x02\x7f\xff\x10\x20\x30\x40\x50"

    assert encode_bytes(source, output, payload) == len(payload)
    assert decode_bytes(output) == payload


def test_encrypted_text_round_trip_requires_password(tmp_path: Path) -> None:
    source = make_png(tmp_path / "cover.png")
    output = tmp_path / "encrypted.png"

    assert encode_text(
        source, output, "top secret", password="correct horse battery staple"
    ) == len(b"top secret")
    assert decode_text(output, password="correct horse battery staple") == "top secret"
    with pytest.raises(PayloadError, match="password|modified"):
        decode_text(output, password="wrong password")


def test_encrypted_binary_round_trip(tmp_path: Path) -> None:
    source = make_png(tmp_path / "cover.png")
    output = tmp_path / "encrypted.png"
    payload = b"\x00\xff\x80binary"

    encode_bytes(source, output, payload, password=" pass with spaces ")

    assert decode_bytes(output, password=" pass with spaces ") == payload


def test_encrypted_payload_authenticates_payload_type() -> None:
    envelope = bytearray(_encrypt_payload(b"data", "password", 1))
    envelope[1] = 2

    with pytest.raises(PayloadError, match="wrong or the payload was modified"):
        _decrypt_payload(bytes(envelope), "password")


def test_binary_file_limit_is_checked_before_full_read(tmp_path: Path) -> None:
    oversized = tmp_path / "too-large.bin"
    oversized.write_bytes(b"x" * (MAX_PAYLOAD_BYTES + 1))

    with pytest.raises(InputError, match="4 MiB limit"):
        encode_file(tmp_path / "does-not-need-to-exist.png", tmp_path / "out.png", oversized)


def test_capacity_failure_does_not_create_output(tmp_path: Path) -> None:
    source = make_png(tmp_path / "small.png", size=(8, 8))
    output = tmp_path / "encoded.png"

    with pytest.raises(CapacityError, match="short by"):
        encode_text(source, output, "payload too large for this image")
    assert not output.exists()


def test_existing_output_is_not_overwritten(tmp_path: Path) -> None:
    source = make_png(tmp_path / "cover.png")
    output = tmp_path / "encoded.png"
    output.write_bytes(b"keep this")

    with pytest.raises(OutputError, match="already exists"):
        encode_text(source, output, "message")
    assert output.read_bytes() == b"keep this"


def test_input_and_output_must_differ(tmp_path: Path) -> None:
    source = make_png(tmp_path / "cover.png")

    with pytest.raises(OutputError, match="must be different"):
        encode_text(source, source, "message", force=True)


def test_non_png_input_rejected(tmp_path: Path) -> None:
    source = tmp_path / "not.png"
    source.write_bytes(b"not an image")

    with pytest.raises(InputError, match="Invalid or unsafe PNG"):
        decode_text(source)


def test_modified_payload_rejected(tmp_path: Path) -> None:
    source = make_png(tmp_path / "cover.png", size=(64, 64))
    output = tmp_path / "encoded.png"
    encode_text(source, output, "integrity check")
    with Image.open(output) as encoded:
        pixels = bytearray(encoded.tobytes())
        # Flip a payload bit immediately after the fixed header.
        pixels[46 * 8] ^= 1
        Image.frombytes(encoded.mode, encoded.size, bytes(pixels)).save(output)

    with pytest.raises(PayloadError, match="integrity check failed"):
        decode_text(output)


def test_image_without_shadowhide_header_rejected(tmp_path: Path) -> None:
    image = make_png(tmp_path / "plain.png")

    with pytest.raises(PayloadError, match="No ShadowHide payload"):
        decode_text(image)
