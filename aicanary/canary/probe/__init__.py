"""Outbound probe against public AI tools (component 4).

A scheduled job queries public AI tools with the *inverse or adjacent*
question (never the canary fact itself) and, separately, with a
verbatim-completion extraction test, then fuzzy-matches responses against each
active canary's unique tokens. Any match is logged as a probe hit.

This is the least reliable component by design (public tools have no stable
API), so it degrades gracefully: a tool that is unreachable is logged and
skipped, never crashing the run.

base.py                - ProbeTarget interface + registry.
copilot_playwright.py  - reference target: Copilot free tier via browser.
runner.py              - orchestrates probes across active canaries.
"""

from .base import ProbeTarget, ProbeResponse, register_probe, get_probe
from . import copilot_playwright  # noqa: F401  (registers itself)

__all__ = ["ProbeTarget", "ProbeResponse", "register_probe", "get_probe"]
