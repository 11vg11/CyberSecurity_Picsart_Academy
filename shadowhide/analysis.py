"""Cautious, ShadowHide-specific image analysis reports."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from . import __version__
from .core import has_shadowhide_header, inspect_png


def analyze_png(path: Path) -> dict[str, object]:
    """Create an evidence-oriented report with explicit scope and limitations."""
    image_facts = inspect_png(path)
    header_found = has_shadowhide_header(path)
    return {
        "tool": "ShadowHide",
        "version": __version__,
        "analyzed_at": datetime.now(timezone.utc).isoformat(),
        "input": image_facts,
        "methods": ["PNG validation", "file size and dimensions", "SHA-256", "ShadowHide v1 header check"],
        "observations": [
            {
                "kind": "shadowhide_header",
                "status": "recognized" if header_found else "not_recognized",
                "confidence": "confirmed" if header_found else "none",
            }
        ],
        "limitations": [
            "This check only recognizes ShadowHide version 1 headers.",
            "A missing header does not show that an image is free of hidden data.",
            "LSB changes, metadata, appended data, and statistical patterns are not analyzed.",
            "This is not malware scanning or a verdict that the file is safe.",
        ],
    }
