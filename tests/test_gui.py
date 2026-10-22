import queue

from shadowhide import gui


def test_gui_operation_indicator_starts_and_stops(monkeypatch) -> None:
    class FakeVariable:
        value = ""

        def set(self, value: str) -> None:
            self.value = value

    class FakeProgress:
        def __init__(self) -> None:
            self.started = False
            self.visible = False

        def pack(self, **kwargs: object) -> None:
            assert kwargs == {"side": "right", "padx": (8, 0)}
            self.visible = True

        def start(self, interval: int) -> None:
            assert interval == 10
            self.started = True

        def stop(self) -> None:
            self.started = False

        def pack_forget(self) -> None:
            self.visible = False

    class FakeRoot:
        def after(self, delay: int, callback) -> None:
            assert delay == 100
            assert callable(callback)

    class ImmediateThread:
        def __init__(self, *, target, name: str, daemon: bool) -> None:
            self.target = target
            assert name == "shadowhide-operation"
            assert daemon

        def start(self) -> None:
            self.target()

    app = object.__new__(gui.ShadowHideApp)
    app._busy = False
    app._tasks = queue.Queue()
    app.status = FakeVariable()
    app.progress = FakeProgress()
    app.root = FakeRoot()
    results: list[object] = []
    monkeypatch.setattr(gui.threading, "Thread", ImmediateThread)

    app._start_task("Inspecting PNG…", lambda: "complete", results.append)

    assert app._busy
    assert app.progress.started
    assert app.progress.visible
    app._poll_tasks()

    assert not app._busy
    assert not app.progress.started
    assert not app.progress.visible
    assert results == ["complete"]


def test_gui_reports_missing_tkinter_cleanly(monkeypatch, capsys) -> None:
    monkeypatch.setattr(gui, "tk", None)

    assert gui.main() == 2
    assert "Tkinter is not installed" in capsys.readouterr().err
