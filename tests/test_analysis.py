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
