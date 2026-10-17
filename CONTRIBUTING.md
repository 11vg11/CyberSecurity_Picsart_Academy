# Contributing

Contributions are welcome. For security-sensitive changes, explain the threat addressed and
include regression tests. Do not submit private evidence, real secrets, or malware samples.

## Development setup

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e '.[dev]'
pytest
```

Keep changes focused, use type hints, and update tests and documentation to match behavior.
The supported Python baseline is 3.10; run tests on the Python version targeted by your
change before submitting it.
