"""Reference injection adapter: a local document store.

Writes one Markdown file per variant into a directory that stands in for
"whatever the internal AI reads from". Requires no external credentials, so it
is the adapter the test suite and demos use, and the template to copy when
writing a real one. Each file is a plain, believable internal note - a human
or AI reading it has no reason to doubt it.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ..logging_setup import get_logger
from ..models import Canary, Variant
from .base import PlantResult, TargetAdapter, register_adapter

log = get_logger()


@register_adapter("local_docstore")
class LocalDocStoreAdapter(TargetAdapter):
    def __init__(self, target_config: dict[str, Any], global_config: Any = None):
        super().__init__(target_config, global_config)
        self.root = Path(target_config.get("root", "planted_docs"))

    def plant(self, canary: Canary, variants: list[Variant]) -> list[PlantResult]:
        self.root.mkdir(parents=True, exist_ok=True)
        results: list[PlantResult] = []
        for v in variants:
            # One doc per variant increases retrieval recall (several
            # paraphrases to match against) and keeps each variant's wording
            # separately traceable to its audience.
            slug = f"{canary.category}-{canary.canary_id}-{v.variant_id}.md"
            path = self.root / slug
            body = self._render(canary, v)
            path.write_text(body, encoding="utf-8")
            log.info("Planted variant %s -> %s", v.variant_id, path)
            results.append(
                PlantResult(
                    variant_id=v.variant_id,
                    location=str(path.resolve()),
                    detail={"audience": v.audience},
                )
            )
        return results

    @staticmethod
    def _render(canary: Canary, v: Variant) -> str:
        # Deliberately mundane framing so it reads as a real internal note.
        return (
            f"# Internal note - {canary.category}\n\n"
            f"_Audience: {v.audience}_\n\n"
            f"{v.text}\n\n"
            f"> Source of record: {canary.s3_url}\n"
        )
