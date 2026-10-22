#!/usr/bin/env python3
"""Friendly GUI for offline demos and authorized local/public passive scans."""
import ipaddress
import json
import socket
import threading
import tkinter as tk
import webbrowser
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from urllib.parse import urlparse

import scanner


def is_loopback_url(url: str) -> bool:
    try:
        parsed = urlparse(url.strip())
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            return False
        port = parsed.port
        if port is not None and not 1 <= port <= 65535:
            return False
        if parsed.username or parsed.password:
            return False
        hostname = parsed.hostname.lower()
        if hostname == "localhost":
            return True
        return ipaddress.ip_address(hostname).is_loopback
    except ValueError:
        return False


def is_public_https_url(url: str) -> bool:
    try:
        parsed = urlparse(url.strip())
        if (
            parsed.scheme.lower() != "https"
            or not parsed.hostname
            or parsed.username
            or parsed.password
        ):
            return False
        port = parsed.port
        if port is not None and not 1 <= port <= 65535:
            return False
        hostname = parsed.hostname
        try:
            resolved = [ipaddress.ip_address(hostname)]
        except ValueError:
            answers = socket.getaddrinfo(
                hostname,
                port or 443,
                type=socket.SOCK_STREAM,
            )
            resolved = [
                ipaddress.ip_address(answer[4][0])
                for answer in answers
            ]
        return bool(resolved) and all(address.is_global for address in resolved)
    except (OSError, ValueError):
        return False


def offline_demo_report() -> dict:
    """Return clearly labeled sample findings without doing network I/O."""
    return {
        "target": "Offline demo (simulated; no network requests)",
        "scan_time": scanner.datetime.datetime.now(
            scanner.datetime.timezone.utc
        ).isoformat().replace("+00:00", "Z"),
        "findings": [
            {
                "module": "HTTP Security Headers",
                "severity": "medium",
                "title": "Sample: Missing Content-Security-Policy",
                "detail": "This is illustrative demo data, not a result from a real scan.",
            },
            {
                "module": "Software Fingerprinting",
                "severity": "info",
                "title": "Sample: Technology detected",
                "detail": "This is illustrative demo data, not a result from a real scan.",
            },
        ],
    }


class CronosGUI:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("Cronos Security Scanner")
        self.root.geometry("860x620")
        self.root.minsize(680, 480)
        self.result = None
        self.last_report_path = None
        self.check_widgets = {}

        container = ttk.Frame(root, padding=20)
        container.pack(fill=tk.BOTH, expand=True)

        ttk.Label(
            container,
            text="Cronos",
            font=("TkDefaultFont", 22, "bold"),
        ).pack(anchor=tk.W)
        ttk.Label(
            container,
            text="Low-impact checks for local labs and authorized websites.",
            wraplength=780,
        ).pack(anchor=tk.W, pady=(2, 16))

        mode_frame = ttk.LabelFrame(container, text="Choose a mode", padding=12)
        mode_frame.pack(fill=tk.X)
        self.mode = tk.StringVar(value="offline")
        ttk.Radiobutton(
            mode_frame,
            text="Offline demo (sample results only; no requests)",
            variable=self.mode,
            value="offline",
            command=self._update_mode,
        ).pack(anchor=tk.W)
        ttk.Radiobutton(
            mode_frame,
            text="Scan a local Docker or home lab (real checks; no internet required)",
            variable=self.mode,
            value="local",
            command=self._update_mode,
        ).pack(anchor=tk.W, pady=(6, 0))
        ttk.Radiobutton(
            mode_frame,
            text="Check an authorized public website (HTTPS, passive checks only)",
            variable=self.mode,
            value="internet",
            command=self._update_mode,
        ).pack(anchor=tk.W, pady=(6, 0))

        target_frame = ttk.Frame(container)
        target_frame.pack(fill=tk.X, pady=(12, 4))
        self.target_label = ttk.Label(target_frame, text="Local site URL:")
        self.target_label.pack(side=tk.LEFT)
        self.url = tk.StringVar(value="http://127.0.0.1:3000")
        self.url_entry = ttk.Entry(target_frame, textvariable=self.url)
        self.url_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(8, 0))

        ttk.Label(
            container,
            text="Docker: publish a port (for example, -p 3000:80) and use "
                 "http://127.0.0.1:3000. Public mode accepts HTTPS websites only "
                 "and checks only the supplied page; it does not probe paths, log in, "
                 "or query external vulnerability services. Scan only with permission.",
            wraplength=780,
        ).pack(anchor=tk.W, pady=(0, 8))

        checks_frame = ttk.LabelFrame(container, text="Checks to run", padding=8)
        checks_frame.pack(fill=tk.X, pady=(0, 10))
        check_options = (
            ("headers", "HTTP security headers", True),
            ("tls", "TLS certificate / protocols", True),
            ("cookies", "Cookie attributes", True),
            ("debug", "Framework debug indicators", True),
            ("sri", "Third-party script SRI", True),
            ("fingerprint", "Technology fingerprints", True),
            ("sensitive_files", "Common exposed paths (local only)", False),
            ("sbom", "Dependency manifest checks (local only)", False),
        )
        self.check_vars = {}
        for index, (key, label, default) in enumerate(check_options):
            variable = tk.BooleanVar(value=default)
            self.check_vars[key] = variable
            checkbox = ttk.Checkbutton(
                checks_frame,
                text=label,
                variable=variable,
                command=self._update_selection,
            )
            checkbox.grid(
                row=index // 2,
                column=index % 2,
                sticky=tk.W,
                padx=(0, 14),
                pady=2,
            )
            self.check_widgets[key] = checkbox
        ttk.Label(
            checks_frame,
            text="Public mode automatically skips local-path and dependency checks.",
        ).grid(row=4, column=0, columnspan=2, sticky=tk.W, pady=(4, 0))

        self.authorized = tk.BooleanVar(value=False)
        self.authorization = ttk.Checkbutton(
            container,
            text="I own this system or have explicit permission to test it.",
            variable=self.authorized,
        )
        self.authorization.pack(anchor=tk.W, pady=(0, 12))

        action_frame = ttk.Frame(container)
        action_frame.pack(fill=tk.X)
        self.run_button = ttk.Button(
            action_frame, text="Run check", command=self.run
        )
        self.run_button.pack(side=tk.LEFT)
        self.save_button = ttk.Button(
            action_frame, text="Save JSON report", command=self.save_report,
            state=tk.DISABLED,
        )
        self.save_button.pack(side=tk.LEFT, padx=(8, 0))
        self.open_button = ttk.Button(
            action_frame,
            text="Open saved report",
            command=self.open_report,
            state=tk.DISABLED,
        )
        self.open_button.pack(side=tk.LEFT, padx=(8, 0))
        self.status = tk.StringVar(value="Ready. Offline demo is selected.")
        ttk.Label(action_frame, textvariable=self.status).pack(
            side=tk.LEFT, padx=(14, 0)
        )
        self.progress = ttk.Progressbar(action_frame, mode="determinate", length=140)
        self.progress.pack(side=tk.RIGHT, padx=(8, 0))

        results_frame = ttk.LabelFrame(container, text="Results", padding=8)
        results_frame.pack(fill=tk.BOTH, expand=True, pady=(14, 0))
        self.output = tk.Text(results_frame, wrap=tk.WORD, height=16, state=tk.DISABLED)
        scrollbar = ttk.Scrollbar(
            results_frame, orient=tk.VERTICAL, command=self.output.yview
        )
        self.output.configure(yscrollcommand=scrollbar.set)
        self.output.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self._update_mode()

    def _update_mode(self):
        mode = self.mode.get()
        target_mode = mode in ("local", "internet")
        entry_state = tk.NORMAL if target_mode else tk.DISABLED
        self.url_entry.configure(state=entry_state)
        self.authorization.configure(
            state=tk.NORMAL if target_mode else tk.DISABLED
        )
        self._update_selection()
        if mode == "offline":
            self.target_label.configure(text="Target URL:")
            self.status.set("Offline demo selected; no requests will be made.")
        elif mode == "local":
            self.target_label.configure(text="Local site URL:")
            self.status.set("Local-only mode selected.")
        else:
            self.target_label.configure(text="Public HTTPS URL:")
            self.status.set("Authorized public-site mode selected.")

    def _update_selection(self):
        public_mode = self.mode.get() == "internet"
        for key in ("sensitive_files", "sbom"):
            widget_state = tk.DISABLED if public_mode else tk.NORMAL
            self.check_widgets[key].configure(state=widget_state)

    def run(self):
        mode = self.mode.get()
        if mode == "offline":
            self._show_result(offline_demo_report())
            self.status.set("Offline demo complete. No network requests were made.")
            return

        target = self.url.get().strip()
        if mode == "local" and not is_loopback_url(target):
            messagebox.showerror(
                "Local URL required",
                "Enter a URL using localhost, 127.0.0.1, or the IPv6 loopback address ::1.",
                parent=self.root,
            )
            return
        if mode == "internet" and not is_public_https_url(target):
            messagebox.showerror(
                "Public HTTPS URL required",
                "Enter an HTTPS URL whose hostname resolves only to public IP addresses.",
                parent=self.root,
            )
            return
        selected_checks = {
            key for key, variable in self.check_vars.items() if variable.get()
        }
        if not selected_checks:
            messagebox.showwarning(
                "Choose checks",
                "Select at least one check to run.",
                parent=self.root,
            )
            return
        if not self.authorized.get():
            messagebox.showwarning(
                "Confirm authorization",
                "Confirm that you own the target or have explicit permission to test it.",
                parent=self.root,
            )
            return

        self.run_button.configure(state=tk.DISABLED)
        self.save_button.configure(state=tk.DISABLED)
        self.open_button.configure(state=tk.DISABLED)
        self.progress.configure(value=0, maximum=1)
        self.status.set(
            "Checking your local service…"
            if mode == "local"
            else "Running limited passive checks on the public HTTPS page…"
        )
        threading.Thread(
            target=self._run_scan,
            args=(
                target,
                mode == "internet",
                selected_checks,
            ),
            daemon=True,
        ).start()

    def _run_scan(
        self, target: str, passive_only: bool, selected_checks: set[str]
    ):
        try:
            report = scanner.run_scan(
                target,
                aggressive=False,
                include_sbom=not passive_only,
                passive_only=passive_only,
                selected_checks=selected_checks,
                progress_callback=lambda name, index, total: self.root.after(
                    0, self._update_progress, name, index, total
                ),
            )
        except Exception as error:
            self.root.after(0, self._show_error, str(error))
            return
        self.root.after(0, self._finish_local_scan, report)

    def _update_progress(self, name: str, index: int, total: int):
        self.progress.configure(maximum=max(total, 1), value=index - 1)
        self.status.set(f"Check {index}/{total}: {name}")

    def _finish_local_scan(self, report: dict):
        self._show_result(report)
        error_count = len(report.get("errors", []))
        self.status.set(
            f"Check complete: {len(report['findings'])} finding(s), "
            f"{error_count} check error(s)."
        )
        self.progress.configure(maximum=1, value=1)
        self.run_button.configure(state=tk.NORMAL)

    def _show_error(self, error: str):
        self.status.set("Local check failed.")
        self.run_button.configure(state=tk.NORMAL)
        self.progress.configure(value=0)
        messagebox.showerror("Check failed", error, parent=self.root)

    def _show_result(self, report: dict):
        self.result = report
        self.output.configure(state=tk.NORMAL)
        self.output.delete("1.0", tk.END)
        self.output.insert(tk.END, f"Target: {report['target']}\n")
        self.output.insert(tk.END, f"Scan time: {report['scan_time']}\n")
        self.output.insert(tk.END, f"Findings: {len(report['findings'])}\n\n")
        if report.get("errors"):
            self.output.insert(tk.END, "Checks that failed:\n")
            for error in report["errors"]:
                self.output.insert(
                    tk.END,
                    f"  [!] {error['module']}: {error['error_type']}: "
                    f"{error['message']}\n",
                )
            self.output.insert(tk.END, "\n")
        for finding in report["findings"]:
            severity = finding.get("severity", "info").upper()
            self.output.insert(
                tk.END,
                f"[{severity}] {finding.get('title', 'Untitled finding')}\n",
            )
            self.output.insert(
                tk.END,
                f"  Module: {finding.get('module', 'Unknown')}\n"
                f"  Details: {finding.get('detail', '')}\n\n",
            )
        self.output.configure(state=tk.DISABLED)
        self.save_button.configure(state=tk.NORMAL)

    def save_report(self):
        if self.result is None:
            return
        path = filedialog.asksaveasfilename(
            parent=self.root,
            title="Save Cronos report",
            defaultextension=".html",
            filetypes=[("HTML report", "*.html"), ("JSON report", "*.json")],
            initialfile="cronos-report.html",
        )
        if not path:
            return
        try:
            if path.lower().endswith(".html"):
                from reports import html_report
                html_report.write(self.result, path)
            else:
                with open(path, "w", encoding="utf-8") as report_file:
                    json.dump(self.result, report_file, indent=2)
        except OSError as error:
            messagebox.showerror("Could not save report", str(error), parent=self.root)
            return
        self.last_report_path = Path(path).resolve()
        self.open_button.configure(state=tk.NORMAL)
        self.status.set(f"Report saved to {path}")

    def open_report(self):
        if self.last_report_path is not None and self.last_report_path.is_file():
            webbrowser.open(self.last_report_path.as_uri())


def main():
    root = tk.Tk()
    CronosGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
