# Security policy and threat model

## Scope

ShadowHide accepts PNG input and hides/retrieves UTF-8 text or binary data by changing the
least significant bit of RGB color samples. Optional password protection uses authenticated
encryption. The inspection and analysis features are limited and are intended for authorized
security research, education, and forensic workflows.

## Security properties and limitations

- LSB encoding is **not encryption**. Anyone who knows or guesses the format can extract
  an unencrypted payload. Use a strong, unique password to encrypt sensitive payloads.
- Encrypted payloads use AES-GCM with PBKDF2-HMAC-SHA256 key derivation (600,000 iterations),
  a random 16-byte salt, and a random 12-byte nonce. The encrypted envelope is authenticated.
  Password strength remains essential; a weak password can be guessed offline.
- Unencrypted payloads use SHA-256 to detect accidental corruption; it does not authenticate
  the author or prevent deliberate modification.
- Basic inspection is not a malware scanner or a general steganography detector. An
  unrecognized image is not evidence that it contains no hidden data.
- Resizing, recompression, palette conversion, or other image editing can destroy the
  payload. Only PNG is supported for reliable round trips.
- Pillow parses untrusted image data. Keep dependencies current and process hostile inputs
  in an appropriately isolated environment.

## Defensive limits

The application restricts compressed input file size to 256 MiB, decoded image size to
12 million pixels, and plaintext payload size to 4 MiB. It validates PNG structure and dimensions
before processing and checks embedding capacity before writing. Output is never written over
the input. Existing output files are refused unless replacement is explicitly confirmed
through the GUI or `--force` is supplied on the CLI.

## Reporting vulnerabilities

Please report security issues privately to the project maintainers before public disclosure.
Do not include confidential payloads or sensitive evidence in reports.
