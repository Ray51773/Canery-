"""Internal-injection adapters (component 2).

The adapter interface is ``plant(canary, variants, target_system) -> PlantResult``.
One reference adapter targeting a local doc store ships for offline testing,
and a Confluence adapter ships as the configured production target. Add more
by subclassing ``TargetAdapter`` and registering it - see base.py.
"""

from .base import TargetAdapter, PlantResult, register_adapter, get_adapter
from . import local_docstore  # noqa: F401  (registers itself on import)
from . import confluence      # noqa: F401  (registers itself on import)

__all__ = ["TargetAdapter", "PlantResult", "register_adapter", "get_adapter"]
