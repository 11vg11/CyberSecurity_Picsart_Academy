import queue
from pathlib import Path

from PIL import Image

from shadowhide import gui
from shadowhide.core import decode_bytes


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


def test_gui_debounces_utf8_payload_count() -> None:
    class FakeRoot:
        cancelled: list[str] = []
        callback = None

        def after_cancel(self, job: str) -> None:
            self.cancelled.append(job)

        def after(self, delay: int, callback) -> str:
            assert delay == 150
            self.callback = callback
            return "next-job"

    class FakeText:
        modified = True

        def edit_modified(self, value: bool | None = None) -> bool:
            if value is not None:
                self.modified = value
            return self.modified

        def get(self, start: str, end: str) -> str:
            assert (start, end) == ("1.0", "end-1c")
            return "🌍"

    class FakeVariable:
        value = ""

        def set(self, value: str) -> None:
            self.value = value

    app = object.__new__(gui.ShadowHideApp)
    app.root = FakeRoot()
    app._payload_count_job = "previous-job"
    app.message = FakeText()
    app.payload_count = FakeVariable()

    app._schedule_payload_count()
    assert app.root.cancelled == ["previous-job"]
    app.root.callback()

    assert app.payload_count.value == "4 bytes of UTF-8 text"
    assert app._payload_count_job is None


def test_gui_encodes_binary_file_and_extracts_it(tmp_path: Path) -> None:
    class FakeVariable:
        def __init__(self, value: str) -> None:
            self.value = value

        def get(self) -> str:
            return self.value

    class FakeStatus:
        value = ""

        def set(self, value: str) -> None:
            self.value = value

    cover = tmp_path / "cover.png"
    payload_file = tmp_path / "payload.bin"
    encoded = tmp_path / "encoded.png"
    extracted = tmp_path / "extracted.bin"
    payload_file.write_bytes(b"\x00\xffbinary payload\x80")
    Image.new("RGB", (128, 128), (20, 40, 60)).save(cover)

    app = object.__new__(gui.ShadowHideApp)
    app.cover_path = FakeVariable(str(cover))
    app.encoded_path = FakeVariable(str(encoded))
    app.encode_mode = FakeVariable("binary")
    app.binary_input_path = FakeVariable(str(payload_file))
    app.encode_password = FakeVariable("secret")
    app.status = FakeStatus()
    app._confirm_overwrite = lambda _path: False
    app._start_task = lambda _description, operation, on_success: on_success(operation())

    app._encode()

    assert decode_bytes(encoded, password="secret") == payload_file.read_bytes()
    assert "file bytes" in app.status.value

    app.decode_path = FakeVariable(str(encoded))
    app.decode_output = FakeVariable(str(extracted))
    app.decode_password = FakeVariable("secret")
    app._confirm_overwrite = lambda _path: False

    app._decode_to_file()

    assert extracted.read_bytes() == payload_file.read_bytes()
    assert "Extracted payload saved" in app.status.value
