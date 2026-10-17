"""Optional desktop interface for the shared ShadowHide engine."""

from __future__ import annotations

import json
import logging
import queue
import sys
import threading
from concurrent.futures import Future
from pathlib import Path
from typing import Callable, TypeVar

try:
    import tkinter as tk
    from tkinter import filedialog, messagebox, ttk
except ModuleNotFoundError as exc:
    if exc.name not in {"tkinter", "tkinter.filedialog", "tkinter.messagebox", "tkinter.ttk"}:
        raise
    tk = None  # type: ignore[assignment]
    filedialog = messagebox = ttk = None  # type: ignore[assignment]

from . import __version__
from .analysis import analyze_png
from .core import (
    MAX_PAYLOAD_BYTES,
    decode_text,
    encode_text,
    inspect_png,
    png_payload_capacity,
)
from .errors import ShadowHideError
from .paths import write_bytes_safely

LOGGER = logging.getLogger(__name__)
T = TypeVar("T")


class ShadowHideApp:
    """Tkinter UI; long-running image operations execute away from the UI thread."""

    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title(f"ShadowHide {__version__}")
        self.root.geometry("900x700")
        self.root.minsize(720, 560)
        self._tasks: queue.Queue[tuple[Future[object], Callable[[object], None]]] = queue.Queue()
        self._busy = False
        self.last_report: dict[str, object] | None = None

        self._configure_style()
        self.status = tk.StringVar(value="Ready")

        heading = ttk.Frame(root, padding=(20, 16, 20, 8))
        heading.pack(fill="x")
        ttk.Label(heading, text="ShadowHide", style="Title.TLabel").pack(anchor="w")
        ttk.Label(
            heading,
            text="PNG text steganography and limited image inspection",
            style="Subtitle.TLabel",
        ).pack(anchor="w", pady=(2, 0))

        self.notebook = ttk.Notebook(root)
        self.notebook.pack(fill="both", expand=True, padx=20, pady=(4, 10))
        self._build_encode_tab()
        self._build_decode_tab()
        self._build_inspect_tab()
        self._build_analyze_tab()

        footer = ttk.Frame(root, padding=(20, 0, 20, 12))
        footer.pack(fill="x")
        ttk.Label(footer, textvariable=self.status, style="Status.TLabel").pack(side="left")
        ttk.Label(
            footer,
            text="Hiding is not encryption. Analysis is not proof of a clean file.",
            style="Warning.TLabel",
        ).pack(side="right")
        self.root.after(100, self._poll_tasks)
        self.root.protocol("WM_DELETE_WINDOW", self._close)

    def _configure_style(self) -> None:
        style = ttk.Style(self.root)
        if "clam" in style.theme_names():
            style.theme_use("clam")
        style.configure("Title.TLabel", font=("TkDefaultFont", 20, "bold"))
        style.configure("Subtitle.TLabel", foreground="#475569")
        style.configure("Status.TLabel", foreground="#1e3a5f")
        style.configure("Warning.TLabel", foreground="#8a4b08")
        style.configure("Primary.TButton", padding=(12, 7))
        style.configure("TNotebook.Tab", padding=(14, 8))

    def _build_encode_tab(self) -> None:
        frame = self._tab("Encode")
        self.cover_path = tk.StringVar()
        self.encoded_path = tk.StringVar()
        self.capacity_text = tk.StringVar(value="Choose a PNG to check available capacity.")

        self._path_row(frame, "Cover PNG", self.cover_path, self._choose_cover)
        self._path_row(frame, "Output PNG", self.encoded_path, self._choose_encoded_output)
        ttk.Button(frame, text="Check capacity", command=self._check_capacity).pack(
            anchor="e", pady=(0, 8)
        )
        ttk.Label(frame, textvariable=self.capacity_text, style="Subtitle.TLabel").pack(
            anchor="w", pady=(0, 6)
        )
        ttk.Label(frame, text="Text to hide").pack(anchor="w")
        self.message = tk.Text(frame, height=13, wrap="word", undo=True)
        self.message.pack(fill="both", expand=True, pady=(5, 8))
        self.message.bind("<<Modified>>", self._update_payload_count)
        self.payload_count = tk.StringVar(value="0 bytes")
        ttk.Label(frame, textvariable=self.payload_count, style="Subtitle.TLabel").pack(anchor="w")
        ttk.Button(
            frame,
            text="Encode text",
            style="Primary.TButton",
            command=self._encode,
        ).pack(anchor="e", pady=(10, 0))

    def _build_decode_tab(self) -> None:
        frame = self._tab("Decode")
        self.decode_path = tk.StringVar()
        self.decode_output = tk.StringVar()
        self._path_row(frame, "Encoded PNG", self.decode_path, self._choose_decode_input)
        self._path_row(frame, "Save text to (optional)", self.decode_output, self._choose_decode_output)
        buttons = ttk.Frame(frame)
        buttons.pack(fill="x", pady=(4, 8))
        ttk.Button(
            buttons,
            text="Show extracted text",
            style="Primary.TButton",
            command=self._decode_to_view,
        ).pack(side="left")
        ttk.Button(
            buttons,
            text="Extract to file",
            command=self._decode_to_file,
        ).pack(side="left", padx=(8, 0))
        ttk.Label(
            frame,
            text="Text is only displayed after you choose “Show extracted text.” "
            "Extracting to a file avoids placing it in the application window.",
            wraplength=790,
            style="Subtitle.TLabel",
        ).pack(anchor="w", pady=(2, 8))
        self.decoded_text = tk.Text(frame, height=17, wrap="word", state="disabled")
        self.decoded_text.pack(fill="both", expand=True)

    def _build_inspect_tab(self) -> None:
        frame = self._tab("Inspect")
        self.inspect_path = tk.StringVar()
        self._path_row(frame, "PNG image", self.inspect_path, self._choose_inspect_input)
        ttk.Button(
            frame,
            text="Inspect image",
            style="Primary.TButton",
            command=self._inspect,
        ).pack(anchor="e", pady=(0, 10))
        self.inspect_result = tk.Text(frame, height=20, wrap="word", state="disabled")
        self.inspect_result.pack(fill="both", expand=True)

    def _build_analyze_tab(self) -> None:
        frame = self._tab("Analyze")
        self.analyze_path = tk.StringVar()
        self._path_row(frame, "PNG image", self.analyze_path, self._choose_analyze_input)
        controls = ttk.Frame(frame)
        controls.pack(fill="x", pady=(0, 8))
        ttk.Button(
            controls,
            text="Run limited analysis",
            style="Primary.TButton",
            command=self._analyze,
        ).pack(side="left")
        ttk.Button(controls, text="Save JSON report", command=self._save_report).pack(
            side="left", padx=(8, 0)
        )
        self.analysis_result = tk.Text(frame, height=20, wrap="word", state="disabled")
        self.analysis_result.pack(fill="both", expand=True)

    def _tab(self, title: str) -> ttk.Frame:
        frame = ttk.Frame(self.notebook, padding=16)
        self.notebook.add(frame, text=title)
        return frame

    @staticmethod
    def _path_row(
        parent: ttk.Frame, label: str, variable: tk.StringVar, browse: Callable[[], None]
    ) -> None:
        row = ttk.Frame(parent)
        row.pack(fill="x", pady=(0, 9))
        ttk.Label(row, text=label, width=22).pack(side="left", anchor="w")
        ttk.Entry(row, textvariable=variable).pack(side="left", fill="x", expand=True)
        ttk.Button(row, text="Browse…", command=browse).pack(side="left", padx=(8, 0))

    def _choose_cover(self) -> None:
        path = filedialog.askopenfilename(
            title="Select cover PNG",
            filetypes=[("PNG images", "*.png"), ("All files", "*.*")],
        )
        if path:
            self.cover_path.set(path)
            self.capacity_text.set("Checking image capacity…")
            self._start_task(
                "Checking PNG capacity…",
                lambda: png_payload_capacity(Path(path)),
                self._show_capacity,
            )

    def _choose_encoded_output(self) -> None:
        path = filedialog.asksaveasfilename(
            title="Save encoded PNG",
            defaultextension=".png",
            filetypes=[("PNG images", "*.png")],
        )
        if path:
            self.encoded_path.set(path)

    def _choose_decode_input(self) -> None:
        self._choose_png(self.decode_path, "Select encoded PNG")

    def _choose_inspect_input(self) -> None:
        self._choose_png(self.inspect_path, "Select PNG to inspect")

    def _choose_analyze_input(self) -> None:
        self._choose_png(self.analyze_path, "Select PNG to analyze")

    @staticmethod
    def _choose_png(variable: tk.StringVar, title: str) -> None:
        path = filedialog.askopenfilename(
            title=title,
            filetypes=[("PNG images", "*.png"), ("All files", "*.*")],
        )
        if path:
            variable.set(path)

    def _choose_decode_output(self) -> None:
        path = filedialog.asksaveasfilename(title="Save extracted text")
        if path:
            self.decode_output.set(path)

    def _update_payload_count(self, _event: tk.Event[tk.Misc] | None = None) -> None:
        if self.message.edit_modified():
            text = self.message.get("1.0", "end-1c")
            size = len(text.encode("utf-8"))
            self.payload_count.set(f"{size:,} bytes of UTF-8 text")
            self.message.edit_modified(False)

    def _check_capacity(self) -> None:
        path = self.cover_path.get().strip()
        if not path:
            self._show_error("Select a cover PNG first.")
            return
        self.capacity_text.set("Checking image capacity…")
        self._start_task(
            "Checking PNG capacity…",
            lambda: png_payload_capacity(Path(path)),
            self._show_capacity,
        )

    def _show_capacity(self, result: object) -> None:
        capacity = int(result)
        text = self.message.get("1.0", "end-1c")
        payload_bytes = len(text.encode("utf-8"))
        self.capacity_text.set(f"Available payload capacity: {capacity:,} bytes")
        self.status.set(f"Text size: {payload_bytes:,} bytes; image capacity: {capacity:,} bytes.")

    def _encode(self) -> None:
        cover = Path(self.cover_path.get().strip())
        output = Path(self.encoded_path.get().strip())
        text = self.message.get("1.0", "end-1c")
        if not self.cover_path.get().strip() or not self.encoded_path.get().strip():
            self._show_error("Choose both a cover PNG and an output path.")
            return
        if len(text.encode("utf-8")) > MAX_PAYLOAD_BYTES:
            self._show_error("Text exceeds the 4 MiB payload limit.")
            return
        force = self._confirm_overwrite(output)
        if force is None:
            return

        def operation() -> int:
            return encode_text(cover, output, text, force=force)

        self._start_task(
            "Encoding text…",
            operation,
            lambda result: self.status.set(
                f"Encoded {int(result):,} UTF-8 bytes to {output}"
            ),
        )

    def _decode_to_view(self) -> None:
        path = self.decode_path.get().strip()
        if not path:
            self._show_error("Choose an encoded PNG first.")
            return

        def show(result: object) -> None:
            text = str(result)
            display_limit = 250_000
            self.decoded_text.configure(state="normal")
            self.decoded_text.delete("1.0", "end")
            self.decoded_text.insert("1.0", text[:display_limit])
            self.decoded_text.configure(state="disabled")
            if len(text) > display_limit:
                self.status.set(
                    f"Displayed first {display_limit:,} characters; save the full payload to a file."
                )
            else:
                self.status.set(f"Extracted {len(text.encode('utf-8')):,} UTF-8 bytes.")

        self._start_task(
            "Extracting text…",
            lambda: decode_text(Path(path)),
            show,
        )

    def _decode_to_file(self) -> None:
        source_text = self.decode_path.get().strip()
        output_text = self.decode_output.get().strip()
        if not source_text:
            self._show_error("Choose an encoded PNG first.")
            return
        if not output_text:
            self._choose_decode_output()
            output_text = self.decode_output.get().strip()
        if not output_text:
            return
        source = Path(source_text)
        output = Path(output_text)
        force = self._confirm_overwrite(output)
        if force is None:
            return

        def operation() -> Path:
            text = decode_text(source)
            write_bytes_safely(text.encode("utf-8"), source, output, force)
            return output

        self._start_task(
            "Saving extracted text…",
            operation,
            lambda result: self.status.set(f"Extracted text saved to {result}"),
        )

    def _inspect(self) -> None:
        path = self.inspect_path.get().strip()
        if not path:
            self._show_error("Choose a PNG to inspect.")
            return
        self._start_task(
            "Inspecting PNG…",
            lambda: inspect_png(Path(path)),
            lambda result: self._set_text(self.inspect_result, json.dumps(result, indent=2)),
        )

    def _analyze(self) -> None:
        path = self.analyze_path.get().strip()
        if not path:
            self._show_error("Choose a PNG to analyze.")
            return

        def show(result: object) -> None:
            self.last_report = result  # type: ignore[assignment]
            self._set_text(self.analysis_result, json.dumps(result, indent=2, ensure_ascii=False))
            self.status.set(
                "Limited analysis complete. A missing ShadowHide header does not rule out other hidden data."
            )

        self._start_task("Analyzing PNG…", lambda: analyze_png(Path(path)), show)

    def _save_report(self) -> None:
        if self.last_report is None:
            self._show_error("Run an analysis before saving a report.")
            return
        report_path = filedialog.asksaveasfilename(
            title="Save JSON analysis report",
            defaultextension=".json",
            filetypes=[("JSON reports", "*.json"), ("All files", "*.*")],
        )
        if not report_path:
            return
        output = Path(report_path)
        source = Path(str(self.last_report["input"]["path"]))  # type: ignore[index]
        force = self._confirm_overwrite(output)
        if force is None:
            return
        report_data = (json.dumps(self.last_report, indent=2, ensure_ascii=False) + "\n").encode(
            "utf-8"
        )

        def save() -> Path:
            write_bytes_safely(report_data, source, output, force)
            return output

        self._start_task(
            "Saving analysis report…",
            save,
            lambda result: self.status.set(f"Analysis report saved to {result}"),
        )

    @staticmethod
    def _set_text(widget: tk.Text, text: str) -> None:
        widget.configure(state="normal")
        widget.delete("1.0", "end")
        widget.insert("1.0", text)
        widget.configure(state="disabled")

    def _confirm_overwrite(self, output: Path) -> bool | None:
        if output.exists():
            if messagebox.askyesno(
                "Replace existing file?",
                f"This file already exists:\n{output}\n\nReplace it?",
                parent=self.root,
            ):
                return True
            return None
        return False

    def _start_task(
        self,
        description: str,
        operation: Callable[[], T],
        on_success: Callable[[object], None],
    ) -> None:
        if self._busy:
            self.status.set("Please wait for the current operation to finish.")
            return
        self._busy = True
        self.status.set(description)

        future: Future[object] = Future()

        def run() -> None:
            if not future.set_running_or_notify_cancel():
                return
            try:
                future.set_result(operation())
            except Exception as exc:
                future.set_exception(exc)

        threading.Thread(target=run, name="shadowhide-operation", daemon=True).start()
        self._tasks.put((future, on_success))

    def _poll_tasks(self) -> None:
        try:
            future, on_success = self._tasks.get_nowait()
        except queue.Empty:
            self.root.after(100, self._poll_tasks)
            return

        if not future.done():
            self._tasks.put((future, on_success))
            self.root.after(100, self._poll_tasks)
            return

        self._busy = False
        try:
            result = future.result()
            on_success(result)
        except ShadowHideError as exc:
            self.status.set("Operation failed.")
            self._show_error(str(exc))
        except OSError as exc:
            self.status.set("Operation failed.")
            self._show_error(f"File operation failed: {exc}")
        except Exception as exc:
            LOGGER.exception("Unexpected GUI operation failure")
            self.status.set("Operation failed.")
            self._show_error(f"Unexpected error: {exc}")
        self.root.after(100, self._poll_tasks)

    def _show_error(self, message: str) -> None:
        messagebox.showerror("ShadowHide", message, parent=self.root)

    def _close(self) -> None:
        if self._busy and not messagebox.askyesno(
            "Operation in progress",
            "An operation is still running. Close the window anyway?",
            parent=self.root,
        ):
            return
        self.root.destroy()


def main() -> int:
    if tk is None:
        print(
            "shadowhide-gui: Tkinter is not installed for this Python interpreter. "
            "On Ubuntu, install python3-tk for the Python version used by ShadowHide.",
            file=sys.stderr,
        )
        return 2
    try:
        root = tk.Tk()
    except tk.TclError as exc:
        print(
            f"shadowhide-gui: cannot start a desktop window: {exc}\n"
            "Check that a graphical desktop is available and Tk is installed "
            "(on Ubuntu, install python3-tk).",
            file=sys.stderr,
        )
        return 2
    ShadowHideApp(root)
    root.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
