"""Shared, transparent HTTP client with conservative pacing and WAF signals."""
import re
import threading
import time

import requests


WAF_BLOCK_SIGNATURES = (
    r"Attention Required! \| Cloudflare",
    r"cf-error-details",
    r"Request blocked",
    r"Access Denied.*AWS WAF",
    r"The requested URL was rejected",
    r"incapsula",
    r"akamai",
)


class WAFState:
    """Track block responses so callers can stop optional checks."""

    def __init__(self, window: int = 10, block_threshold: int = 4):
        self.lock = threading.Lock()
        self.recent_codes = []
        self.window = window
        self.block_threshold = block_threshold
        self.waf_triggered = False
        self.waf_name = None

    def record(self, status_code: int, body_snippet: str = "") -> None:
        with self.lock:
            self.recent_codes.append(status_code)
            self.recent_codes = self.recent_codes[-self.window:]
            if sum(code in (403, 429) for code in self.recent_codes) >= self.block_threshold:
                self.waf_triggered = True

            for signature in WAF_BLOCK_SIGNATURES:
                if re.search(signature, body_snippet, re.IGNORECASE):
                    self.waf_triggered = True
                    self.waf_name = signature
                    break

    def is_triggered(self) -> bool:
        with self.lock:
            return self.waf_triggered


class ScanHTTPClient:
    def __init__(self, base_url: str, min_delay: float = 0.15, timeout: int = 10):
        self.base_url = base_url
        self.min_delay = max(0.0, min_delay)
        self.timeout = timeout
        self.waf_state = WAFState()
        self._last_request_time = 0.0
        self._lock = threading.Lock()
        self._backoff_level = 0
        self.session = requests.Session()
        self.session.headers.setdefault(
            "User-Agent", "Cronos/1.0 (+authorized-security-assessment)"
        )

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.session.close()

    def _throttle(self) -> None:
        with self._lock:
            delay = self.min_delay * (2 ** self._backoff_level)
            elapsed = time.monotonic() - self._last_request_time
            if elapsed < delay:
                time.sleep(delay - elapsed)
            self._last_request_time = time.monotonic()

    def get(self, url: str, **kwargs):
        self._throttle()
        kwargs.setdefault("timeout", self.timeout)
        response = self.session.get(url, **kwargs)
        self.waf_state.record(
            response.status_code,
            response.text[:2000] if response.text else "",
        )

        if response.status_code in (403, 429):
            self._backoff_level = min(self._backoff_level + 1, 5)
        elif self._backoff_level > 0 and response.status_code < 400:
            self._backoff_level -= 1
        return response

    def passive_mode_recommended(self) -> bool:
        """Return True after repeated block responses or a known block page."""
        return self.waf_state.is_triggered()
