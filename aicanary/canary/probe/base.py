"""Probe target interface and registry.

To add another public AI tool (ChatGPT, Gemini, ...):

  1. Subclass ``ProbeTarget``.
  2. Implement ``ask(prompt) -> ProbeResponse``. If the tool has a legitimate
     API, use it (preferred over browser automation). Otherwise follow the
     Playwright reference target and keep the manual-confirmation gate.
  3. Register with ``@register_probe("name")`` and add a block under
     ``probe.tools`` in config.
  4. ``ask`` must NEVER raise for a tool being unreachable - return a
     ProbeResponse with ``ok=False`` and an ``error`` so the runner logs
     "probe failed, tool unreachable" and moves on.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Callable

_REGISTRY: dict[str, type["ProbeTarget"]] = {}


def register_probe(name: str) -> Callable[[type["ProbeTarget"]], type["ProbeTarget"]]:
    def deco(cls: type["ProbeTarget"]) -> type["ProbeTarget"]:
        _REGISTRY[name] = cls
        cls.probe_name = name
        return cls
    return deco


def get_probe(name: str) -> type["ProbeTarget"]:
    if name not in _REGISTRY:
        raise KeyError(f"Unknown probe target {name!r}; registered: {sorted(_REGISTRY)}")
    return _REGISTRY[name]


@dataclass
class ProbeResponse:
    """Result of asking a public AI tool one prompt.

    ``ok=False`` means the tool was unreachable or errored; the runner logs it
    and continues (graceful degradation), it is never a crash.
    """

    ok: bool
    prompt: str
    text: str = ""
    error: str = ""
    meta: dict[str, Any] = field(default_factory=dict)


class ProbeTarget(ABC):
    probe_name: str = "base"

    def __init__(self, tool_config: dict[str, Any], global_config: Any = None):
        self.config = tool_config
        self.global_config = global_config
        self.enabled = bool(tool_config.get("enabled", True))

    @abstractmethod
    def ask(self, prompt: str) -> ProbeResponse:
        """Send one prompt, return the response. Must not raise for
        unreachability - return ProbeResponse(ok=False, error=...)."""
        raise NotImplementedError

    def close(self) -> None:
        """Release resources (browser, session). Default: nothing."""
