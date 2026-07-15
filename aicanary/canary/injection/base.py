"""Injection adapter interface and registry.

To add a new target surface (a RAG ingest endpoint, a Slack channel, a ticket
system, ...):

  1. Subclass ``TargetAdapter``.
  2. Implement ``plant(canary, variants)`` to push every variant's text into
     the surface, phrased multiple ways (one document/message per variant, or
     one document containing all paraphrases), so an embedding/retrieval index
     built from it has several forms to match against.
  3. Return a ``PlantResult`` per variant with the location it landed at.
  4. Register it: ``@register_adapter("my_adapter")`` on the class, and add a
     block under ``injection.targets`` in config naming ``adapter: my_adapter``.

An adapter's ``__init__`` receives its config block (a dict) plus the global
Config, so it can read secrets from the environment via ``config.env(...)``.
"""

from __future__ import annotations

import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Callable

from ..logging_setup import get_logger
from ..models import Canary, Plant, Variant

log = get_logger()

_REGISTRY: dict[str, type["TargetAdapter"]] = {}


def register_adapter(name: str) -> Callable[[type["TargetAdapter"]], type["TargetAdapter"]]:
    def deco(cls: type["TargetAdapter"]) -> type["TargetAdapter"]:
        _REGISTRY[name] = cls
        cls.adapter_name = name
        return cls
    return deco


def get_adapter(name: str) -> type["TargetAdapter"]:
    if name not in _REGISTRY:
        raise KeyError(
            f"Unknown injection adapter {name!r}; registered: {sorted(_REGISTRY)}"
        )
    return _REGISTRY[name]


@dataclass
class PlantResult:
    """Where one variant landed in a target surface."""

    variant_id: str
    location: str            # file path, page id, URL, message ts
    detail: dict[str, Any] = field(default_factory=dict)


class TargetAdapter(ABC):
    """Base class for a system a canary can be planted into."""

    adapter_name: str = "base"

    def __init__(self, target_config: dict[str, Any], global_config: Any = None):
        self.config = target_config
        self.global_config = global_config
        self.target_system = target_config.get("name", self.adapter_name)

    @abstractmethod
    def plant(self, canary: Canary, variants: list[Variant]) -> list[PlantResult]:
        """Push every variant into the target surface. Must be implemented by
        subclasses. Should raise on hard failure so the caller can log it and
        avoid recording a plant that did not happen."""
        raise NotImplementedError

    def to_plants(self, canary: Canary, results: list[PlantResult]) -> list[Plant]:
        """Helper: turn PlantResults into Plant records for the store."""
        import json

        plants = []
        for r in results:
            plants.append(
                Plant(
                    plant_id="pl_" + uuid.uuid4().hex[:12],
                    canary_id=canary.canary_id,
                    variant_id=r.variant_id,
                    target_system=self.target_system,
                    location=r.location,
                    detail=json.dumps(r.detail) if r.detail else "",
                )
            )
        return plants
