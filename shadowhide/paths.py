"""Safe output file creation helpers."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

from PIL import Image

from .errors import OutputError


def validate_output_path(input_path: Path, output_path: Path, force: bool) -> None:
    if input_path.resolve() == output_path.resolve():
        raise OutputError("Input and output paths must be different.")
    if not output_path.parent.is_dir():
        raise OutputError(f"Output directory does not exist: {output_path.parent}")
    if output_path.exists() and not force:
        raise OutputError(f"Output already exists: {output_path}. Use --force to replace it.")


def save_image_safely(image: Image.Image, input_path: Path, output_path: Path, force: bool) -> None:
    validate_output_path(input_path, output_path, force)
    temp_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            prefix=".shadowhide-", suffix=".png", dir=output_path.parent, delete=False
        ) as temporary:
            temp_path = Path(temporary.name)
        image.save(temp_path, format="PNG")
        if force:
            os.replace(temp_path, output_path)
        else:
            os.link(temp_path, output_path)
            temp_path.unlink()
    except FileExistsError as exc:
        raise OutputError(
            f"Output already exists: {output_path}. Use --force to replace it."
        ) from exc
    except OSError as exc:
        raise OutputError(f"Cannot write output file: {exc}") from exc
    finally:
        if temp_path is not None:
            try:
                temp_path.unlink(missing_ok=True)
            except OSError:
                pass


def write_bytes_safely(data: bytes, input_path: Path, output_path: Path, force: bool) -> None:
    validate_output_path(input_path, output_path, force)
    temp_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            prefix=".shadowhide-", suffix=".tmp", dir=output_path.parent, delete=False
        ) as temporary:
            temp_path = Path(temporary.name)
            temporary.write(data)
            temporary.flush()
            os.fsync(temporary.fileno())
        if force:
            os.replace(temp_path, output_path)
        else:
            os.link(temp_path, output_path)
            temp_path.unlink()
    except FileExistsError as exc:
        raise OutputError(
            f"Output already exists: {output_path}. Use --force to replace it."
        ) from exc
    except OSError as exc:
        raise OutputError(f"Cannot write output file: {exc}") from exc
    finally:
        if temp_path is not None:
            try:
                temp_path.unlink(missing_ok=True)
            except OSError:
                pass
