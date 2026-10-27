import json
from pathlib import Path

from PIL import Image

from shadowhide.analysis import analyze_png


def test_analysis_report_has_facts_methods_and_limitations(tmp_path: Path) -> None:
    image_path = tmp_path / "synthetic.png"
    Image.new("RGB", (32, 24), color=(10, 20, 30)).save(image_path)

    report = analyze_png(image_path)

    assert report["tool"] == "ShadowHide"
    assert report["analyzed_at"]
    assert report["input"]["width"] == 32
    assert "SHA-256" in report["methods"]
    assert report["observations"][0]["status"] == "not_recognized"
    assert any("does not show" in item for item in report["limitations"])
    assert report["forensics"]["metadata"]["count"] >= 0
    assert report["forensics"]["appended_data"]["present"] is False
    assert set(report["forensics"]["channel_lsb_balance"]).issubset({"red", "green", "blue"})
    assert report["forensics"]["channel_lsb_sampled_pixels"] == 32 * 24
    json.dumps(report)


def test_analysis_report_detects_appended_png_data(tmp_path: Path) -> None:
    image_path = tmp_path / "synthetic-appended.png"
    Image.new("RGB", (16, 16), color=(1, 2, 3)).save(image_path)
    image_path.write_bytes(image_path.read_bytes() + b"extra trailing bytes")

    report = analyze_png(image_path)

    assert report["forensics"]["appended_data"]["present"] is True
    assert report["forensics"]["appended_data"]["bytes"] > 0
