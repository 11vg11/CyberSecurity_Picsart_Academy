from shadowhide import gui


def test_gui_reports_missing_tkinter_cleanly(monkeypatch, capsys) -> None:
    monkeypatch.setattr(gui, "tk", None)

    assert gui.main() == 2
    assert "Tkinter is not installed" in capsys.readouterr().err
