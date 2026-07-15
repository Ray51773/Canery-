"""Reference probe target: Microsoft Copilot free tier via Playwright.

  !! ToS / LEGAL NOTE !!
  Copilot free has no stable, sanctioned API. This target automates the public
  web UI with a headful browser. Automating a web UI may violate the tool's
  Terms of Service. This is why:
    * every run is gated behind an explicit manual confirmation
      (``require_confirmation: true`` in config, enforced by the runner), and
    * the security team must decide, per their legal guidance, whether to run
      it. Prefer a legitimate API surface for any tool that offers one (add a
      new ProbeTarget that calls the API instead of driving a browser).

  Web UIs change frequently. The selectors below are best-effort and isolated
  here so they can be updated without touching the rest of the system. If the
  page shape changes, ``ask`` returns ok=False (graceful degradation) rather
  than crashing the scheduled run.

Playwright is an optional dependency (requirements-probe.txt). If it is not
installed, this target reports itself unavailable instead of importing at
module load, so the core tool works without a browser engine.
"""

from __future__ import annotations

from typing import Any

from ..logging_setup import get_logger
from .base import ProbeResponse, ProbeTarget, register_probe

log = get_logger()

COPILOT_URL = "https://copilot.microsoft.com/"


@register_probe("copilot_playwright")
class CopilotPlaywrightProbe(ProbeTarget):
    def __init__(self, tool_config: dict[str, Any], global_config: Any = None):
        super().__init__(tool_config, global_config)
        self.headless = bool(tool_config.get("headless", False))
        self.timeout_ms = int(tool_config.get("timeout_seconds", 60)) * 1000
        self._pw = None
        self._browser = None

    def _ensure_browser(self):
        """Lazily import and launch Playwright. Import failure -> unavailable,
        not a crash."""
        if self._browser is not None:
            return
        try:
            from playwright.sync_api import sync_playwright
        except ImportError as exc:
            raise RuntimeError(
                "Playwright not installed. `pip install -r requirements-probe.txt` "
                "and `python -m playwright install chromium`"
            ) from exc
        self._pw = sync_playwright().start()
        self._browser = self._pw.chromium.launch(headless=self.headless)

    def ask(self, prompt: str) -> ProbeResponse:
        try:
            self._ensure_browser()
        except RuntimeError as exc:
            log.warning("Copilot probe unavailable: %s", exc)
            return ProbeResponse(ok=False, prompt=prompt, error=str(exc))

        page = None
        try:
            page = self._browser.new_page()
            page.set_default_timeout(self.timeout_ms)
            page.goto(COPILOT_URL, wait_until="domcontentloaded")

            # Best-effort selectors; kept in one place for easy maintenance.
            box = page.locator("textarea, [contenteditable='true']").first
            box.wait_for(state="visible")
            box.click()
            box.fill(prompt)
            box.press("Enter")

            # Wait for a response to render. We cannot rely on a specific
            # selector long-term, so wait for network to settle then scrape
            # the visible conversation text.
            page.wait_for_load_state("networkidle")
            page.wait_for_timeout(3000)
            text = page.inner_text("body")

            return ProbeResponse(ok=True, prompt=prompt, text=text,
                                 meta={"url": COPILOT_URL})
        except Exception as exc:  # graceful degradation - never crash the run
            log.warning("Copilot probe failed, tool unreachable/changed: %s", exc)
            return ProbeResponse(ok=False, prompt=prompt, error=str(exc))
        finally:
            if page is not None:
                try:
                    page.close()
                except Exception:
                    pass

    def close(self) -> None:
        try:
            if self._browser is not None:
                self._browser.close()
            if self._pw is not None:
                self._pw.stop()
        except Exception:  # pragma: no cover
            pass
        finally:
            self._browser = None
            self._pw = None
