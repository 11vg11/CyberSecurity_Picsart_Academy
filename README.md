# ShadowHide

ShadowHide is a local command-line toolkit for embedding and extracting UTF-8 text or binary
payloads in PNG images using least-significant-bit (LSB) encoding, plus basic image inspection.
It also supports password-based authenticated encryption and limited forensic reporting. It is
not a general-purpose forensic scanner.

## Features

- Encode and decode UTF-8 text, raw binary payloads, and password-protected payloads in RGB/RGBA PNGs.
- Versioned payload header with a payload type, length, and SHA-256 corruption check.
- Capacity validation and bounded image/file processing.
- Basic inspect/analyze JSON reports with file hash, metadata, trailing-data checks, and explicit limitations.
- Optional lightweight desktop GUI for the same encode/decode/inspect/analyze engine.
- No network access, telemetry, or automatic execution of extracted data.

## Project status

**Available now**

- Installable Python package and `shadowhide` CLI with `encode`, `decode`, `inspect`,
  `analyze`, and `version` commands.
- Version 1 PNG RGB/RGBA LSB payload format, including UTF-8 round trips, raw binary
  payload support, authenticated password encryption, capacity checks, payload length
  validation, and a SHA-256 corruption check.
- Input size and decoded image limits; safe output writing that avoids accidental overwrite.
- Basic inspection (dimensions, mode, size, capacity, and SHA-256) and a JSON analysis
  report with ShadowHide header recognition, metadata summary, trailing-data scan, and
  bounded LSB balance sampling.
- An initial Tkinter GUI with Encode, Decode, Inspect, and Analyze tabs, sharing the core
  engine with the CLI, including binary file embedding and extraction.
- Scrollable GUI text areas and a visible activity indicator while background operations run.
- Automated tests using synthetic images, including encryption, payload integrity, and
  malformed-input cases.

**GUI environment note:** the GUI code and launcher are present, but Tkinter was unavailable
in the Python 3.14 environment used during development, so launching and visually validating
the desktop window there was not possible. Install Tk support for the Python interpreter
used by the virtual environment before running `shadowhide-gui`.

**Not implemented yet:** general-purpose steganography detection, full bit-plane visualization,
operation cancellation controls, and broader release engineering. A negative ShadowHide-header
check is not evidence that an image contains no hidden data or is safe.

## Installation

Ubuntu and other systems with Python 3.10 or newer:

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install .
```

For development and tests, install `python -m pip install -e '.[dev]'`.
The GUI uses Python's standard-library Tkinter. On Ubuntu, install it if needed with
`sudo apt install python3-tk`.

## Quick start

```bash
shadowhide encode --input cover.png --output encoded.png --text "Test message"
shadowhide decode --input encoded.png --stdout
shadowhide inspect --input encoded.png
shadowhide analyze --input encoded.png --report report.json
```

Launch the desktop interface with:

```bash
shadowhide-gui
```

Or, from a source checkout, run `python -m shadowhide.gui`. The GUI includes Encode, Decode,
Inspect, and Analyze tabs. Encode text or select a binary file; decode text to view or extract
either text or binary payloads to a file. Longer operations run off the UI thread, with a
visible activity indicator and scrollable text areas. Extracted files and reports use safe
output handling and ask before replacing an existing file.

The input image is not modified. By default, an existing output is not overwritten; use
`--force` to replace it deliberately. Decode does not print payload contents unless
`--stdout` is explicitly selected. It can instead write them to a file using `--output`.

To encode text from a file, use `--text-file message.txt`; this avoids putting the text
directly in shell command history. To hide arbitrary binary data, use `--binary-file payload.bin`.
Provide exactly one of `--text`, `--text-file`, or `--binary-file`. Protect either payload
type with `--password` to add authenticated encryption using PBKDF2-HMAC-SHA256 and
AES-GCM. For interactive use, prefer `--password-stdin` so the password is not placed in shell
history or visible in the process argument list.

## Command reference

```text
shadowhide encode --input COVER.png --output RESULT.png
                  (--text TEXT | --text-file FILE | --binary-file FILE)
                  [--password PASS | --password-stdin] [--force] [--json]
shadowhide decode --input IMAGE.png [--output FILE | --stdout]
                  [--password PASS | --password-stdin] [--force] [--json]
shadowhide inspect --input IMAGE.png [--json]
shadowhide analyze --input IMAGE.png [--report FILE] [--json]
shadowhide version
```

`--json` emits a machine-readable result to standard output. The `analyze --report` option
writes the JSON analysis report to a file. Errors are written to standard error and return a
nonzero exit code. No command requires an interactive prompt.

## Supported images and payload format

Input must be a valid PNG. Images are normalized to RGB or RGBA as needed; alpha is
preserved when present, and only RGB channels carry bits. The image's visible appearance is
normally unchanged, but its pixel values and metadata may change.

The payload format is version 1: `SHDW` magic (4 bytes), version (1 byte), payload type
(1 byte), payload length (8-byte big-endian unsigned integer), SHA-256 digest (32 bytes),
then payload bytes. The payload type distinguishes UTF-8 text (`1`), raw binary data (`2`),
and encrypted payloads (`3`). The encrypted payload envelope contains an envelope version,
original payload type, PBKDF2 iteration count, random 16-byte salt, random 12-byte nonce, and
AES-GCM ciphertext with its authentication tag. AES-GCM authenticates the envelope metadata
as associated data. PBKDF2-HMAC-SHA256 uses 600,000 iterations; these parameters are fixed for
this envelope version. The complete header and payload are embedded one bit per RGB channel
sample, most-significant bit first. Unknown versions, unknown payload types, invalid lengths,
wrong-password decrypts, and digest mismatches are rejected.

## Security and limitations

Steganography is not encryption. An unencrypted payload is extractable by anyone who knows
the format; its checksum detects accidental damage only, not deliberate modification. When
using encryption, AES-GCM authenticates the protected payload and envelope. Use a strong,
unique password; a weak password can be guessed offline.

LSB data can be lost by resizing, recompression, or image editing. The analyzer reports
basic facts and recognizes ShadowHide's own header; it cannot detect arbitrary
steganography, establish that an image is clean, or determine whether content is malicious.
See [SECURITY.md](SECURITY.md).

Inputs are bounded to 256 MiB compressed file size, 12 million decoded pixels, and 4 MiB
of payload bytes before encryption. Encryption adds a small fixed envelope overhead. These
limits reduce accidental resource exhaustion but are not a substitute for isolation when
processing hostile files.

## Development and testing

```bash
python -m pip install -e '.[dev]'
pytest
```

Tests use generated synthetic images and temporary paths. The test suite covers text and
binary round trips, authenticated encryption, capacity and output checks, CLI/report behavior,
and GUI startup when Tkinter is unavailable. Run `ruff check .` and
`ruff format --check shadowhide tests` for lint and formatting validation. There are no
performance benchmarks or CI claims in this initial release.

## Project status and roadmap

Work is intentionally staged so later capabilities build on the tested core:

1. **Foundation — implemented:** packaging, PNG validation, text encode/decode, versioned
   payload header, capacity checks, initial CLI, tests, and documentation.
2. **Desktop usability — improved:** Tkinter GUI for text and binary encode/decode, inspection,
   analysis, scrollable text areas, and visible background-operation feedback. Verify behavior
   on supported desktop environments and continue improving accessibility.
3. **Secure payloads — implemented:** binary/file payloads and authenticated encryption with
   PBKDF2-HMAC-SHA256 and AES-GCM are supported; future work focuses on broader release
   hardening and forensics features.
4. **Forensics — in progress:** metadata summaries, PNG trailing-data checks, and bounded
   channel LSB balance sampling are implemented. Bit-plane/channel views, deeper file-format
   validation, and broader evidence-oriented reporting remain planned.
5. **Engineering and release — planned:** expanded malformed-input and compatibility tests,
   linting/type checking, CI and dependency security checks, measured benchmarks, and
   release/install guidance.

Planned items are not supported features yet. The GUI roadmap does not include duplicating
business logic; it will continue to call the same engine as the CLI.

## License

MIT; see [LICENSE](LICENSE).
