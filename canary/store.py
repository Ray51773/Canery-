"""SQLite-backed store for canaries, variants, plants and detection hits.

SQLite is deliberate: a single auditable file, no server to run, easy to back
up and inspect with off-the-shelf tools. All writes go through this module so
the schema stays in one place.
"""

from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from .logging_setup import get_logger
from .models import (
    Canary,
    Plant,
    ProbeHit,
    S3Hit,
    SecretHit,
    Variant,
    INTENT_DETECT,
    VALID_STATUSES,
)

log = get_logger()

_SCHEMA = """
CREATE TABLE IF NOT EXISTS canaries (
    canary_id   TEXT PRIMARY KEY,
    category    TEXT NOT NULL,
    codename    TEXT NOT NULL,
    base_fact   TEXT NOT NULL,
    quarter     TEXT NOT NULL,
    s3_bucket   TEXT,
    s3_key      TEXT,
    s3_url      TEXT,
    status      TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    notes       TEXT DEFAULT '',
    intent                 TEXT NOT NULL DEFAULT 'detect',
    shape                  TEXT,
    payload_source         TEXT,
    guardrail_dependency   TEXT DEFAULT '',
    last_validated_against TEXT DEFAULT ''
);

CREATE TABLE IF NOT EXISTS variants (
    variant_id  TEXT PRIMARY KEY,
    canary_id   TEXT NOT NULL REFERENCES canaries(canary_id) ON DELETE CASCADE,
    text        TEXT NOT NULL,
    marker      TEXT NOT NULL,
    audience    TEXT NOT NULL DEFAULT 'general',
    created_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS plants (
    plant_id       TEXT PRIMARY KEY,
    canary_id      TEXT NOT NULL REFERENCES canaries(canary_id) ON DELETE CASCADE,
    variant_id     TEXT NOT NULL REFERENCES variants(variant_id) ON DELETE CASCADE,
    target_system  TEXT NOT NULL,
    location       TEXT NOT NULL,
    planted_at     TEXT NOT NULL,
    status         TEXT NOT NULL DEFAULT 'active',
    detail         TEXT DEFAULT ''
);

CREATE TABLE IF NOT EXISTS s3_hits (
    hit_id      TEXT PRIMARY KEY,
    canary_id   TEXT,
    s3_bucket   TEXT NOT NULL,
    s3_key      TEXT NOT NULL,
    event_name  TEXT NOT NULL,
    source_ip   TEXT,
    user_agent  TEXT,
    event_time  TEXT NOT NULL,
    raw         TEXT DEFAULT '',
    ingested_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS secret_hits (
    hit_id      TEXT PRIMARY KEY,
    canary_id   TEXT,
    secret_id   TEXT NOT NULL,
    event_name  TEXT NOT NULL,
    source_ip   TEXT,
    user_agent  TEXT,
    event_time  TEXT NOT NULL,
    raw         TEXT DEFAULT '',
    ingested_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS probe_hits (
    hit_id        TEXT PRIMARY KEY,
    canary_id     TEXT NOT NULL,
    variant_id    TEXT,
    tool          TEXT NOT NULL,
    probe_kind    TEXT NOT NULL,
    matched_token TEXT NOT NULL,
    match_score   REAL NOT NULL,
    response_text TEXT NOT NULL,
    probed_at     TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_variants_canary ON variants(canary_id);
CREATE INDEX IF NOT EXISTS idx_plants_canary ON plants(canary_id);
CREATE INDEX IF NOT EXISTS idx_s3_hits_canary ON s3_hits(canary_id);
CREATE INDEX IF NOT EXISTS idx_s3_hits_key ON s3_hits(s3_key);
CREATE INDEX IF NOT EXISTS idx_secret_hits_canary ON secret_hits(canary_id);
CREATE INDEX IF NOT EXISTS idx_probe_hits_canary ON probe_hits(canary_id);
"""

# Columns added after v1. A pre-existing database predates deter mode, so any
# canary already stored is a tracer: the added intent column defaults to
# 'detect', migrating existing rows without touching them.
_CANARY_MIGRATIONS = {
    "intent": "TEXT NOT NULL DEFAULT 'detect'",
    "shape": "TEXT",
    "payload_source": "TEXT",
    "guardrail_dependency": "TEXT DEFAULT ''",
    "last_validated_against": "TEXT DEFAULT ''",
}


class Store:
    """Thin, typed wrapper over the SQLite database."""

    def __init__(self, database_path: str | Path = "canary.db"):
        self.database_path = str(database_path)
        parent = Path(self.database_path).parent
        if str(parent) and not parent.exists():
            parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    @contextmanager
    def _conn(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.database_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _init_schema(self) -> None:
        with self._conn() as conn:
            conn.executescript(_SCHEMA)
            self._migrate(conn)

    def _migrate(self, conn: sqlite3.Connection) -> None:
        """Add columns introduced after v1 to a pre-existing canaries table.
        ADD COLUMN with a default backfills existing rows in place, so stored
        canaries are never broken or lost."""
        cols = {r["name"] for r in conn.execute("PRAGMA table_info(canaries)").fetchall()}
        for name, ddl in _CANARY_MIGRATIONS.items():
            if name not in cols:
                conn.execute(f"ALTER TABLE canaries ADD COLUMN {name} {ddl}")
                log.info("Migrated canaries table: added column %s", name)

    # --- canaries --------------------------------------------------------
    def add_canary(self, c: Canary) -> None:
        with self._conn() as conn:
            conn.execute(
                """INSERT INTO canaries
                   (canary_id, category, codename, base_fact, quarter,
                    s3_bucket, s3_key, s3_url, status, created_at, notes,
                    intent, shape, payload_source, guardrail_dependency,
                    last_validated_against)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (c.canary_id, c.category, c.codename, c.base_fact, c.quarter,
                 c.s3_bucket, c.s3_key, c.s3_url, c.status, c.created_at, c.notes,
                 c.intent, c.shape, c.payload_source, c.guardrail_dependency,
                 c.last_validated_against),
            )
        log.info("Stored %s %s (%s / %s)", c.intent, c.canary_id, c.category, c.codename)

    def get_canary(self, canary_id: str) -> Canary | None:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM canaries WHERE canary_id = ?", (canary_id,)
            ).fetchone()
        return _row_to_canary(row) if row else None

    def list_canaries(self) -> list[Canary]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM canaries ORDER BY created_at DESC"
            ).fetchall()
        return [_row_to_canary(r) for r in rows]

    def update_canary_s3(self, canary_id: str, bucket: str, key: str, url: str) -> None:
        with self._conn() as conn:
            conn.execute(
                "UPDATE canaries SET s3_bucket=?, s3_key=?, s3_url=? WHERE canary_id=?",
                (bucket, key, url, canary_id),
            )

    def set_canary_status(self, canary_id: str, status: str) -> None:
        if status not in VALID_STATUSES:
            raise ValueError(f"Invalid status {status!r}; must be one of {sorted(VALID_STATUSES)}")
        with self._conn() as conn:
            cur = conn.execute(
                "UPDATE canaries SET status=? WHERE canary_id=?", (status, canary_id)
            )
            if cur.rowcount == 0:
                raise KeyError(f"No such canary: {canary_id}")
        log.info("Canary %s status -> %s", canary_id, status)

    def find_canary_by_key(self, s3_key: str) -> Canary | None:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM canaries WHERE s3_key = ?", (s3_key,)
            ).fetchone()
        return _row_to_canary(row) if row else None

    # --- variants --------------------------------------------------------
    def add_variant(self, v: Variant) -> None:
        with self._conn() as conn:
            conn.execute(
                """INSERT INTO variants
                   (variant_id, canary_id, text, marker, audience, created_at)
                   VALUES (?,?,?,?,?,?)""",
                (v.variant_id, v.canary_id, v.text, v.marker, v.audience, v.created_at),
            )

    def list_variants(self, canary_id: str) -> list[Variant]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM variants WHERE canary_id=? ORDER BY created_at", (canary_id,)
            ).fetchall()
        return [_row_to_variant(r) for r in rows]

    def get_variant(self, variant_id: str) -> Variant | None:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM variants WHERE variant_id=?", (variant_id,)
            ).fetchone()
        return _row_to_variant(row) if row else None

    def all_variants(self) -> list[Variant]:
        with self._conn() as conn:
            rows = conn.execute("SELECT * FROM variants").fetchall()
        return [_row_to_variant(r) for r in rows]

    # --- plants ----------------------------------------------------------
    def add_plant(self, p: Plant) -> None:
        with self._conn() as conn:
            conn.execute(
                """INSERT INTO plants
                   (plant_id, canary_id, variant_id, target_system, location,
                    planted_at, status, detail)
                   VALUES (?,?,?,?,?,?,?,?)""",
                (p.plant_id, p.canary_id, p.variant_id, p.target_system, p.location,
                 p.planted_at, p.status, p.detail),
            )
        log.info("Recorded plant %s: canary %s -> %s (%s)",
                 p.plant_id, p.canary_id, p.target_system, p.location)

    def list_plants(self, canary_id: str) -> list[Plant]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM plants WHERE canary_id=? ORDER BY planted_at", (canary_id,)
            ).fetchall()
        return [_row_to_plant(r) for r in rows]

    # --- s3 hits ---------------------------------------------------------
    def add_s3_hit(self, h: S3Hit) -> bool:
        """Insert an S3 hit. Returns False if this hit_id already exists
        (idempotent ingest from an at-least-once queue)."""
        with self._conn() as conn:
            exists = conn.execute(
                "SELECT 1 FROM s3_hits WHERE hit_id=?", (h.hit_id,)
            ).fetchone()
            if exists:
                return False
            conn.execute(
                """INSERT INTO s3_hits
                   (hit_id, canary_id, s3_bucket, s3_key, event_name, source_ip,
                    user_agent, event_time, raw, ingested_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?)""",
                (h.hit_id, h.canary_id, h.s3_bucket, h.s3_key, h.event_name,
                 h.source_ip, h.user_agent, h.event_time, h.raw, h.ingested_at),
            )
        log.warning("S3 honeytoken HIT recorded: canary=%s key=%s ip=%s",
                    h.canary_id, h.s3_key, h.source_ip)
        return True

    def list_s3_hits(self, canary_id: str) -> list[S3Hit]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM s3_hits WHERE canary_id=? ORDER BY event_time", (canary_id,)
            ).fetchall()
        return [_row_to_s3hit(r) for r in rows]

    # --- secret hits (deter-mode Secrets Manager reads) ------------------
    def add_secret_hit(self, h: SecretHit) -> bool:
        """Insert a Secrets Manager read hit. Returns False if this hit_id
        already exists (idempotent ingest from an at-least-once queue)."""
        with self._conn() as conn:
            exists = conn.execute(
                "SELECT 1 FROM secret_hits WHERE hit_id=?", (h.hit_id,)
            ).fetchone()
            if exists:
                return False
            conn.execute(
                """INSERT INTO secret_hits
                   (hit_id, canary_id, secret_id, event_name, source_ip,
                    user_agent, event_time, raw, ingested_at)
                   VALUES (?,?,?,?,?,?,?,?,?)""",
                (h.hit_id, h.canary_id, h.secret_id, h.event_name,
                 h.source_ip, h.user_agent, h.event_time, h.raw, h.ingested_at),
            )
        log.warning("Secrets Manager honeytoken HIT recorded: canary=%s secret=%s ip=%s",
                    h.canary_id, h.secret_id, h.source_ip)
        return True

    def list_secret_hits(self, canary_id: str) -> list[SecretHit]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM secret_hits WHERE canary_id=? ORDER BY event_time", (canary_id,)
            ).fetchall()
        return [_row_to_secrethit(r) for r in rows]

    # --- probe hits ------------------------------------------------------
    def add_probe_hit(self, h: ProbeHit) -> None:
        with self._conn() as conn:
            conn.execute(
                """INSERT INTO probe_hits
                   (hit_id, canary_id, variant_id, tool, probe_kind,
                    matched_token, match_score, response_text, probed_at)
                   VALUES (?,?,?,?,?,?,?,?,?)""",
                (h.hit_id, h.canary_id, h.variant_id, h.tool, h.probe_kind,
                 h.matched_token, h.match_score, h.response_text, h.probed_at),
            )
        log.warning("Probe HIT recorded: canary=%s tool=%s token=%r score=%.1f",
                    h.canary_id, h.tool, h.matched_token, h.match_score)

    def list_probe_hits(self, canary_id: str) -> list[ProbeHit]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM probe_hits WHERE canary_id=? ORDER BY probed_at", (canary_id,)
            ).fetchall()
        return [_row_to_probehit(r) for r in rows]


# --- row -> model helpers ------------------------------------------------
def _rget(r: sqlite3.Row, key: str, default=None):
    """Tolerant column read: a row from an older DB may lack newer columns."""
    try:
        val = r[key]
    except (IndexError, KeyError):
        return default
    return val if val is not None else default


def _row_to_canary(r: sqlite3.Row) -> Canary:
    return Canary(
        canary_id=r["canary_id"], category=r["category"], codename=r["codename"],
        base_fact=r["base_fact"], quarter=r["quarter"], s3_bucket=r["s3_bucket"],
        s3_key=r["s3_key"], s3_url=r["s3_url"], status=r["status"],
        created_at=r["created_at"], notes=r["notes"] or "",
        intent=_rget(r, "intent", INTENT_DETECT) or INTENT_DETECT,
        shape=_rget(r, "shape"),
        payload_source=_rget(r, "payload_source"),
        guardrail_dependency=_rget(r, "guardrail_dependency", "") or "",
        last_validated_against=_rget(r, "last_validated_against", "") or "",
    )


def _row_to_variant(r: sqlite3.Row) -> Variant:
    return Variant(
        variant_id=r["variant_id"], canary_id=r["canary_id"], text=r["text"],
        marker=r["marker"], audience=r["audience"], created_at=r["created_at"],
    )


def _row_to_plant(r: sqlite3.Row) -> Plant:
    return Plant(
        plant_id=r["plant_id"], canary_id=r["canary_id"], variant_id=r["variant_id"],
        target_system=r["target_system"], location=r["location"],
        planted_at=r["planted_at"], status=r["status"], detail=r["detail"] or "",
    )


def _row_to_s3hit(r: sqlite3.Row) -> S3Hit:
    return S3Hit(
        hit_id=r["hit_id"], canary_id=r["canary_id"], s3_bucket=r["s3_bucket"],
        s3_key=r["s3_key"], event_name=r["event_name"], source_ip=r["source_ip"],
        user_agent=r["user_agent"], event_time=r["event_time"], raw=r["raw"] or "",
        ingested_at=r["ingested_at"],
    )


def _row_to_secrethit(r: sqlite3.Row) -> SecretHit:
    return SecretHit(
        hit_id=r["hit_id"], canary_id=r["canary_id"], secret_id=r["secret_id"],
        event_name=r["event_name"], source_ip=r["source_ip"],
        user_agent=r["user_agent"], event_time=r["event_time"], raw=r["raw"] or "",
        ingested_at=r["ingested_at"],
    )


def _row_to_probehit(r: sqlite3.Row) -> ProbeHit:
    return ProbeHit(
        hit_id=r["hit_id"], canary_id=r["canary_id"], variant_id=r["variant_id"],
        tool=r["tool"], probe_kind=r["probe_kind"], matched_token=r["matched_token"],
        match_score=r["match_score"], response_text=r["response_text"],
        probed_at=r["probed_at"],
    )
