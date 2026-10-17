"""Command-line interface for ShadowHide."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Sequence

from . import __version__
from .analysis import analyze_png
from .core import (
    MAX_PAYLOAD_BYTES,
    decode_text,
    encode_text,
    inspect_png,
)
from .errors import ShadowHideError
from .paths import write_bytes_safely


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="shadowhide",
        description="Encode and extract UTF-8 text in PNG files using LSB steganography.",
        epilog="Example: shadowhide encode --input cover.png --output hidden.png --text 'hello'",
    )
    commands = parser.add_subparsers(dest="command", required=True)

    encode = commands.add_parser("encode", help="embed UTF-8 text in a PNG")
    encode.add_argument("--input", required=True, type=Path, help="cover PNG image")
    encode.add_argument("--output", required=True, type=Path, help="new PNG output path")
    text_group = encode.add_mutually_exclusive_group(required=True)
    text_group.add_argument("--text", help="text to embed")
    text_group.add_argument("--text-file", type=Path, help="UTF-8 file containing text to embed")
    encode.add_argument("--force", action="store_true", help="replace an existing output file")
    encode.add_argument("--json", action="store_true", help="emit a JSON result")

    decode = commands.add_parser("decode", help="extract a ShadowHide text payload")
    decode.add_argument("--input", required=True, type=Path, help="encoded PNG image")
    decode.add_argument("--output", type=Path, help="write decoded text to a new file")
    decode.add_argument("--stdout", action="store_true", help="explicitly print decoded text")
    decode.add_argument("--force", action="store_true", help="replace an existing output file")
    decode.add_argument("--json", action="store_true", help="emit a JSON result")

    inspect = commands.add_parser("inspect", help="show basic PNG facts and SHA-256")
    inspect.add_argument("--input", required=True, type=Path, help="PNG image")
    inspect.add_argument("--json", action="store_true", help="emit a JSON result")

    analyze = commands.add_parser("analyze", help="run limited ShadowHide-aware PNG checks")
    analyze.add_argument("--input", required=True, type=Path, help="PNG image")
    analyze.add_argument("--report", type=Path, help="write the JSON report to a file")
    analyze.add_argument("--json", action="store_true", help="emit the JSON report to stdout")

    commands.add_parser("version", help="show installed version")
    return parser


def _read_text_file(path: Path) -> str:
    try:
        with path.open("rb") as source:
            payload = source.read(MAX_PAYLOAD_BYTES + 1)
        if len(payload) > MAX_PAYLOAD_BYTES:
            raise ShadowHideError(
                f"Text payload file exceeds the {MAX_PAYLOAD_BYTES // (1024 * 1024)} MiB safety limit."
            )
        return payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ShadowHideError("Text payload file must contain valid UTF-8.") from exc
    except OSError as exc:
        raise ShadowHideError(f"Cannot read text payload file: {exc}") from exc


def _write_json_report(report: dict[str, object], input_path: Path, output: Path, force: bool) -> None:
    encoded = (json.dumps(report, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
    write_bytes_safely(encoded, input_path, output, force)


def _run(args: argparse.Namespace) -> int:
    if args.command == "version":
        print(__version__)
        return 0

    if args.command == "encode":
        text = args.text if args.text is not None else _read_text_file(args.text_file)
        if args.text_file is not None and args.text_file.resolve() == args.output.resolve():
            raise ShadowHideError("Text input and output paths must be different.")
        count = encode_text(args.input, args.output, text, args.force)
        result = {"status": "encoded", "output": str(args.output), "payload_bytes": count}
        if args.json:
            print(json.dumps(result))
        else:
            print(f"Encoded {count} payload bytes to {args.output}")
        return 0

    if args.command == "decode":
        if args.output is not None and args.stdout:
            raise ShadowHideError("Choose either --output or --stdout, not both.")
        if args.stdout and args.json:
            raise ShadowHideError("Choose either --stdout or --json for decoded output.")
        text = decode_text(args.input)
        if args.stdout:
            sys.stdout.write(text)
            if not text.endswith("\n"):
                sys.stdout.write("\n")
        elif args.output is not None:
            write_bytes_safely(text.encode("utf-8"), args.input, args.output, args.force)
            if args.json:
                print(json.dumps({"status": "decoded", "output": str(args.output)}))
            else:
                print(f"Decoded text written to {args.output}")
        elif args.json:
            print(json.dumps({"status": "decoded", "payload_bytes": len(text.encode("utf-8"))}))
        else:
            print("A valid text payload was extracted. Specify --output or --stdout to retrieve it.")
        return 0

    if args.command == "inspect":
        result = inspect_png(args.input)
        print(json.dumps(result, indent=2) if args.json else _format_inspection(result))
        return 0

    if args.command == "analyze":
        report = analyze_png(args.input)
        if args.report:
            _write_json_report(report, args.input, args.report, False)
        if args.json:
            print(json.dumps(report, indent=2))
        elif args.report:
            print(f"Limited analysis report written to {args.report}")
            print("No general steganography or malware-detection claim is made.")
        else:
            print(_format_inspection(report["input"]))
            state = report["observations"][0]["status"]
            print(f"ShadowHide v1 header: {state}")
            print("A missing header does not show that the image is free of hidden data.")
        return 0

    raise ShadowHideError("Unknown command.")


def _format_inspection(result: dict[str, object]) -> str:
    return "\n".join(
        [
            f"Format: {result['format']}",
            f"Dimensions: {result['width']} × {result['height']}",
            f"Mode: {result['mode']}",
            f"File size: {result['file_size_bytes']} bytes",
            f"LSB payload capacity: {result['lsb_capacity_bytes']} bytes",
            f"SHA-256: {result['sha256']}",
        ]
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    try:
        return _run(args)
    except ShadowHideError as exc:
        if getattr(args, "json", False):
            print(json.dumps({"error": str(exc)}))
        else:
            print(f"shadowhide: error: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("shadowhide: interrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
