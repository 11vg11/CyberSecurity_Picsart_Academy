from pathlib import Path

import pytest
from PIL import Image

from shadowhide.core import decode_text, encode_text
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
