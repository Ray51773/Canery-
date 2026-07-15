"""Fabricated-fact (canary) generator - component 1.

Produces internal-sounding facts that are entirely synthetic. Each canary
carries at least one statistically unique token (an invented codename plus an
S3 key) that cannot plausibly coincide with real data, so a later hit is
unambiguous rather than a coincidence. Multiple variants are generated per
canary, each with its own per-variant marker and audience tag, implementing
the barium-meal trick: the specific wording that leaks identifies the source.

No real company data is ever used. Codenames are invented from syllables;
numbers are random; phrases are assembled from generic word lists.
"""

from __future__ import annotations

import random
import uuid
from typing import Any

import yaml

from .models import Canary, Variant

# Syllables for invented codenames. These are nonsense-but-pronounceable so
# they read like real internal codenames while being statistically unique.
_CODENAME_PREFIXES = [
    "Zeph", "Quor", "Vand", "Mira", "Talix", "Orlo", "Nyx", "Cira",
    "Pol", "Verd", "Xan", "Lum", "Kry", "Sund", "Ferr", "Alba",
]
_CODENAME_SUFFIXES = [
    "yrine", "vex", "olis", "adne", "on", "ida", "elle", "orax",
    "una", "ith", "aire", "ova", "ex", "yl", "orin", "essa",
]

# Generic, non-identifying phrase parts for the per-variant marker phrase.
_PHRASE_ADJ = [
    "amber", "cobalt", "hollow", "quiet", "northbound", "seventh",
    "folded", "distant", "copper", "narrow", "silent", "outer",
]
_PHRASE_NOUN = [
    "lattice", "meridian", "harbor", "cascade", "ledger", "quorum",
    "beacon", "threshold", "corridor", "anchor", "vector", "relay",
]

_QUARTERS = ["Q1", "Q2", "Q3", "Q4"]


class GeneratorError(Exception):
    pass


class CanaryGenerator:
    """Generates canaries and their variants from category templates."""

    def __init__(self, categories: dict[str, Any], seed: int | None = None):
        if not categories:
            raise GeneratorError("No categories provided to generator")
        self.categories = categories
        self._rng = random.Random(seed)

    @classmethod
    def from_file(cls, path: str, seed: int | None = None) -> "CanaryGenerator":
        with open(path, "r", encoding="utf-8") as fh:
            cats = yaml.safe_load(fh) or {}
        return cls(cats, seed=seed)

    # --- token builders --------------------------------------------------
    def _codename(self) -> str:
        return "Project " + self._rng.choice(_CODENAME_PREFIXES) + self._rng.choice(_CODENAME_SUFFIXES)

    def _phrase(self) -> str:
        return f"{self._rng.choice(_PHRASE_ADJ)} {self._rng.choice(_PHRASE_NOUN)}"

    def _odd_number(self, category: str) -> str:
        """A deliberately specific, odd number - the statistically unique
        numeric token. Financials/legal/exec read as currency; incident reads
        as a count. Two decimal places and non-round values make accidental
        collision with real figures vanishingly unlikely."""
        if category in ("financials", "exec_comms", "legal"):
            whole = self._rng.randint(1_000_000, 90_000_000)
            cents = self._rng.randint(1, 99)
            return f"{whole:,}.{cents:02d}"
        # counts / durations
        return str(self._rng.randint(1013, 98_717))

    # --- generation ------------------------------------------------------
    def generate(
        self,
        category: str,
        n_variants: int = 3,
        audiences: list[str] | None = None,
    ) -> tuple[Canary, list[Variant]]:
        """Generate one canary and ``n_variants`` variants.

        The codename and (later-filled) S3 URL are shared across all variants;
        the {number}/{phrase} markers differ per variant so a leak's wording
        traces the source. ``audiences`` optionally names who each variant is
        issued to (team or individual) for per-source tracing; if shorter than
        n_variants, remaining variants are tagged "general".
        """
        if category not in self.categories:
            raise GeneratorError(
                f"Unknown category {category!r}; known: {sorted(self.categories)}"
            )
        cat = self.categories[category]
        templates: list[str] = cat.get("templates", [])
        if not templates:
            raise GeneratorError(f"Category {category!r} has no templates")

        canary_id = "can_" + uuid.uuid4().hex[:12]
        codename = self._codename()
        quarter = self._rng.choice(_QUARTERS)
        audiences = audiences or []

        # The S3 URL placeholder is filled in later by the honeytoken step; we
        # use a stable sentinel now so base_fact/variant text is coherent and
        # can be rewritten in place once the real key exists.
        s3_placeholder = "s3://<pending-honeytoken>/<pending>.pdf"

        # Canonical (base) fact: first template, first marker.
        base_marker_num = self._odd_number(category)
        base_phrase = self._phrase()
        base_fact = templates[0].format(
            codename=codename, number=base_marker_num, phrase=base_phrase,
            quarter=quarter, s3_url=s3_placeholder,
        )

        canary = Canary(
            canary_id=canary_id,
            category=category,
            codename=codename,
            base_fact=base_fact,
            quarter=quarter,
            s3_url=s3_placeholder,
        )

        variants: list[Variant] = []
        for i in range(max(1, n_variants)):
            template = templates[i % len(templates)]
            # Per-variant markers: an odd number and a distinctive phrase, both
            # unique to this variant so the exact wording is traceable.
            number = self._odd_number(category)
            phrase = self._phrase()
            text = template.format(
                codename=codename, number=number, phrase=phrase,
                quarter=quarter, s3_url=s3_placeholder,
            )
            audience = audiences[i] if i < len(audiences) else "general"
            # The primary variant marker is whichever token is most distinctive
            # for this category: the currency/count number, plus the phrase.
            marker = f"{number} | {phrase}"
            variants.append(
                Variant(
                    variant_id="var_" + uuid.uuid4().hex[:12],
                    canary_id=canary_id,
                    text=text,
                    marker=marker,
                    audience=audience,
                )
            )

        return canary, variants

    def inverse_probes(self, category: str, quarter: str) -> list[str]:
        """The adjacent questions the outbound probe should ask for this
        category. These deliberately never contain the codename or unique
        token - we ask around the fact, never feed it in."""
        cat = self.categories.get(category, {})
        out = []
        for q in cat.get("inverse_probe", []):
            out.append(q.format(quarter=quarter))
        return out


def rewrite_s3_url(text: str, new_url: str) -> str:
    """Replace the pending-honeytoken sentinel in generated text with the real
    S3 URL once the honeytoken object exists."""
    return text.replace("s3://<pending-honeytoken>/<pending>.pdf", new_url)
