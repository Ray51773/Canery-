"""Data models for canaries, variants, plants and detection hits.

These mirror the SQLite schema in ``store.py``. Kept as plain dataclasses so
they are trivial to serialize (dashboard, JSON export) and test.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any


def utcnow_iso() -> str:
    """UTC timestamp in ISO-8601 with a trailing Z. Used everywhere for
    consistent, sortable, timezone-explicit times."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# Canary lifecycle states.
STATUS_CREATED = "created"      # generated, not yet planted
STATUS_PLANTED = "planted"      # pushed into at least one target surface
STATUS_TRIGGERED = "triggered"  # at least one detection point fired
STATUS_RETIRED = "retired"      # deliberately decommissioned
VALID_STATUSES = {STATUS_CREATED, STATUS_PLANTED, STATUS_TRIGGERED, STATUS_RETIRED}


@dataclass
class Canary:
    """One underlying fabricated fact.

    ``codename`` and the S3 reference (``s3_bucket``/``s3_key``) are the
    canary-level unique tokens: they are shared across every variant, so any
    leak is unambiguously *this* canary rather than a coincidence.
    """

    canary_id: str
    category: str
    codename: str
    base_fact: str
    quarter: str
    s3_bucket: str | None = None
    s3_key: str | None = None
    s3_url: str | None = None
    status: str = STATUS_CREATED
    created_at: str = field(default_factory=utcnow_iso)
    notes: str = ""

    def unique_tokens(self) -> list[str]:
        """Canary-level tokens the probe/fuzzy matcher looks for."""
        tokens = [self.codename]
        if self.s3_key:
            tokens.append(self.s3_key)
        return [t for t in tokens if t]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Variant:
    """One rewritten form of a canary, optionally tagged to an audience.

    ``marker`` is the variant-level unique token (an odd number or a
    distinctive phrase) that differs per variant, so the *specific* wording
    that leaks tells you which team/individual it came from - the barium-meal
    trick. ``audience`` records who that variant was issued to.
    """

    variant_id: str
    canary_id: str
    text: str
    marker: str
    audience: str = "general"
    created_at: str = field(default_factory=utcnow_iso)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Plant:
    """A record that a variant was pushed into a target surface."""

    plant_id: str
    canary_id: str
    variant_id: str
    target_system: str
    location: str            # page id, file path, URL - where it landed
    planted_at: str = field(default_factory=utcnow_iso)
    status: str = "active"   # active / removed
    detail: str = ""         # adapter-specific extra info (JSON string)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class S3Hit:
    """An object-level access event on a honeytoken key (from CloudTrail)."""

    hit_id: str
    canary_id: str
    s3_bucket: str
    s3_key: str
    event_name: str          # GetObject / HeadObject
    source_ip: str
    user_agent: str
    event_time: str
    raw: str = ""            # full raw event JSON, for audit
    ingested_at: str = field(default_factory=utcnow_iso)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ProbeHit:
    """A match between a public-AI tool's response and a canary token."""

    hit_id: str
    canary_id: str
    tool: str
    probe_kind: str          # "inverse_question" or "extraction"
    matched_token: str
    match_score: float
    response_text: str
    variant_id: str | None = None
    probed_at: str = field(default_factory=utcnow_iso)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
