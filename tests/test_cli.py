import json
from pathlib import Path

from PIL import Image

from shadowhide.cli import main


def test_cli_encode_decode_redacts_payload_by_default(tmp_path: Path, capsys) -> None:
    source = tmp_path / "cover.png"
    output = tmp_path / "encoded.png"
    Image.new("RGB", (64, 64), color=(80, 90, 100)).save(source)

    assert main(["encode", "--input", str(source), "--output", str(output), "--text", "secret"]) == 0
    capsys.readouterr()
    assert main(["decode", "--input", str(output)]) == 0
    result = capsys.readouterr()
    assert "secret" not in result.out
    assert "Specify --output or --stdout" in result.out


def test_cli_decode_to_stdout_is_explicit(tmp_path: Path, capsys) -> None:
    source = tmp_path / "cover.png"
    output = tmp_path / "encoded.png"
    Image.new("RGB", (64, 64), color=(80, 90, 100)).save(source)
    main(["encode", "--input", str(source), "--output", str(output), "--text", "hello"])
    capsys.readouterr()

    assert main(["decode", "--input", str(output), "--stdout"]) == 0
    assert capsys.readouterr().out == "hello\n"


def test_json_analysis_report_and_file_export(tmp_path: Path, capsys) -> None:
    source = tmp_path / "cover.png"
    report = tmp_path / "report.json"
    Image.new("RGB", (64, 64), color=(80, 90, 100)).save(source)

    assert main(["analyze", "--input", str(source), "--report", str(report), "--json"]) == 0
    stdout_report = json.loads(capsys.readouterr().out)
    file_report = json.loads(report.read_text(encoding="utf-8"))
    assert stdout_report == file_report
    assert stdout_report["observations"][0]["status"] == "not_recognized"
    assert "does not show" in stdout_report["limitations"][1]
    assert stdout_report["analyzed_at"]
    assert stdout_report["methods"]


def test_cli_returns_nonzero_for_invalid_input(tmp_path: Path, capsys) -> None:
    source = tmp_path / "bad.png"
    source.write_bytes(b"bad")

    assert main(["inspect", "--input", str(source)]) == 2
    assert "error:" in capsys.readouterr().err
