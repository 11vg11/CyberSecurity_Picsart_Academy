import io
import json
from pathlib import Path

from PIL import Image

from shadowhide import cli
from shadowhide.cli import main


def test_cli_encode_decode_redacts_payload_by_default(tmp_path: Path, capsys) -> None:
    source = tmp_path / "cover.png"
    output = tmp_path / "encoded.png"
    Image.new("RGB", (64, 64), color=(80, 90, 100)).save(source)

    assert (
        main(["encode", "--input", str(source), "--output", str(output), "--text", "secret"]) == 0
    )
    capsys.readouterr()
    assert main(["decode", "--input", str(output)]) == 0
    result = capsys.readouterr()
    assert "secret" not in result.out
    assert "Specify --output or --stdout" in result.out


def test_cli_binary_file_round_trip(tmp_path: Path, capsys) -> None:
    source = tmp_path / "cover.png"
    payload = tmp_path / "payload.bin"
    output = tmp_path / "encoded.png"
    decoded = tmp_path / "decoded.bin"
    Image.new("RGB", (64, 64), color=(80, 90, 100)).save(source)
    payload.write_bytes(b"\x00\x01\x02\x7f\xff\x10\x20\x30")

    assert (
        main(
            [
                "encode",
                "--input",
                str(source),
                "--output",
                str(output),
                "--binary-file",
                str(payload),
            ]
        )
        == 0
    )
    capsys.readouterr()
    assert main(["decode", "--input", str(output), "--output", str(decoded)]) == 0
    assert decoded.read_bytes() == payload.read_bytes()
    assert "binary" in capsys.readouterr().out.lower()


def test_cli_decode_with_password_round_trip(tmp_path: Path, capsys) -> None:
    source = tmp_path / "cover.png"
    output = tmp_path / "encoded.png"
    Image.new("RGB", (64, 64), color=(80, 90, 100)).save(source)

    assert (
        main(
            [
                "encode",
                "--input",
                str(source),
                "--output",
                str(output),
                "--text",
                "hidden",
                "--password",
                "s3cr3t",
            ]
        )
        == 0
    )
    capsys.readouterr()
    assert main(["decode", "--input", str(output), "--password", "s3cr3t", "--stdout"]) == 0
    assert capsys.readouterr().out == "hidden\n"


def test_cli_accepts_password_from_stdin(tmp_path: Path, monkeypatch, capsys) -> None:
    source = tmp_path / "cover.png"
    output = tmp_path / "encoded.png"
    Image.new("RGB", (64, 64), color=(80, 90, 100)).save(source)

    monkeypatch.setattr(cli.sys, "stdin", io.StringIO("secret\n"))
    assert (
        main(
            [
                "encode",
                "--input",
                str(source),
                "--output",
                str(output),
                "--text",
                "hidden",
                "--password-stdin",
            ]
        )
        == 0
    )
    capsys.readouterr()

    monkeypatch.setattr(cli.sys, "stdin", io.StringIO("secret\n"))
    assert main(["decode", "--input", str(output), "--password-stdin", "--stdout"]) == 0
    assert capsys.readouterr().out == "hidden\n"


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
