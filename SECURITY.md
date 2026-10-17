# Security policy and threat model

## Scope

ShadowHide 0.1.0 accepts PNG input and hides/retrieves UTF-8 text by changing the least
significant bit of RGB color samples. It also provides basic file inspection. It is intended
for authorized security research, education, and forensic workflows.

## Security properties and limitations

- LSB encoding is **not encryption**. Anyone who knows or guesses the format can extract
  the payload. Do not embed secrets unless they have been encrypted separately.
- SHA-256 in the payload header detects accidental corruption; it does not authenticate the
  author or prevent deliberate modification.
- Basic inspection is not a malware scanner or a general steganography detector. An
  unrecognized image is not evidence that it contains no hidden data.
- Resizing, recompression, palette conversion, or other image editing can destroy the
  payload. Only PNG is supported for reliable round trips.
- Pillow parses untrusted image data. Keep dependencies current and process hostile inputs
  in an appropriately isolated environment.

## Defensive limits

The application restricts compressed input file size to 256 MiB, decoded image size to
12 million pixels, and text payload size to 4 MiB. It validates PNG structure and dimensions
before processing and checks embedding capacity before writing. Output is never written over
the input. Existing output files are refused unless replacement is explicitly confirmed
through the GUI or `--force` is supplied on the CLI.

## Reporting vulnerabilities

Please report security issues privately to the project maintainers before public disclosure.
Do not include confidential payloads or sensitive evidence in reports.
