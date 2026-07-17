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

import json
import random
import uuid
from typing import Any

import yaml

from .models import Canary, Variant, INTENT_DETER


# Decoy resource shapes for deter mode. Mirrors the shapes offered by the
# browser console (bomb.html). The payload is placed where a reading agent
# would ingest it; everything else is synthetic filler.
def _wrap_secrets_manager(payload: str, asset: str) -> str:
    return json.dumps({
        "username": f"svc-{asset}",
        "engine": "postgres",
        "host": f"{asset}.db.internal",
        "port": 5432,
        "note": payload,
    }, indent=2)


def _wrap_env(payload: str, asset: str) -> str:
    esc = payload.replace('"', '\\"')
    return (f"# {asset} service environment\nSERVICE_NAME={asset}\n"
            f"LOG_LEVEL=info\nREGION=us-east-1\nDEPLOY_NOTE=\"{esc}\"")


def _wrap_aws_credentials(payload: str, asset: str) -> str:
    return (f"[{asset}]\naws_access_key_id=AKIAEXAMPLE0DECOY000\n"
            f"aws_secret_access_key=wJalrDECOYnotarealkeyEXAMPLEKEY0000decoy0\n"
            f"# operator note: {payload}")


def _wrap_dns_txt(payload: str, asset: str) -> str:
    esc = payload.replace('"', '\\"')
    return f'_note.{asset}.decoy.example.com.   300   IN   TXT   "{esc}"'


def _wrap_iam_role(payload: str, asset: str) -> str:
    return f"Role name: {asset}-automation-role\nDescription: {payload}"


DETER_SHAPES = {
    "secrets_manager": _wrap_secrets_manager,
    "env": _wrap_env,
    "aws_credentials": _wrap_aws_credentials,
    "dns_txt": _wrap_dns_txt,
    "iam_role": _wrap_iam_role,
}

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

    def generate_deter(
        self,
        payload: str,
        shape: str = "secrets_manager",
        assets: list[str] | None = None,
        n_variants: int = 3,
        payload_source: str = "user_supplied",
        guardrail_dependency: str = "",
        validations: list[dict[str, Any]] | None = None,
        label: str | None = None,
    ) -> tuple[Canary, list[Variant]]:
        """Build a context bomb (intent=deter). The generator branches here at
        the top on intent: a bomb has no fabricated fact, codename or S3
        tracer token - the user-supplied ``payload`` is the whole artefact, and
        efficacy is an empirical property recorded in ``validations``, never
        invented. Variants are per-asset (same payload, distinct decoy assets),
        so fingerprinting one asset's exact bytes does not disable the rest."""
        if not payload or not payload.strip():
            raise GeneratorError("A deter artefact requires a payload string")
        if shape not in DETER_SHAPES:
            raise GeneratorError(
                f"Unknown shape {shape!r}; known: {sorted(DETER_SHAPES)}"
            )
        wrap = DETER_SHAPES[shape]
        assets = assets or []
        canary_id = "bomb_" + uuid.uuid4().hex[:12]
        base = (label or "").strip() or f"{shape} decoy"

        variants: list[Variant] = []
        for i in range(max(1, n_variants)):
            asset = assets[i] if i < len(assets) else f"asset-{i + 1}"
            variants.append(
                Variant(
                    variant_id="asset_" + uuid.uuid4().hex[:12],
                    canary_id=canary_id,
                    text=wrap(payload, asset),
                    marker=asset,          # the decoy asset name identifies the variant
                    audience=asset,
                )
            )

        canary = Canary(
            canary_id=canary_id,
            category="context_bomb",
            codename=base,
            base_fact=payload,
            quarter="n/a",
            intent=INTENT_DETER,
            shape=shape,
            payload_source=payload_source,
            guardrail_dependency=guardrail_dependency,
            last_validated_against=json.dumps(validations or []),
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
