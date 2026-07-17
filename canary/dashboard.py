"""Correlation dashboard / report (component 5).

The one view a human actually looks at. For each canary it shows: where and
when it was planted, S3 access hits, public-AI probe hits, and current status.
Clarity over cleverness: a plain, dense CLI report, plus a JSON dump for
piping into anything else.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from .models import INTENT_DETER
from .store import Store

# Human-readable status markers. Kept ASCII so the report is copy-paste safe.
_STATUS_MARK = {
    "created": "[ ] created",
    "planted": "[o] planted",
    "triggered": "[!] TRIGGERED",
    "retired": "[x] retired",
}


def _validation_freshness(c) -> dict[str, Any]:
    """Days since the most recent validation of a deter artefact, with an
    amber(>=90)/red(>=180)/unvalidated state. The only signal that a vendor
    safety change has silently degraded the control."""
    dates = []
    for v in c.validations():
        try:
            dates.append(datetime.strptime(v.get("date", ""), "%Y-%m-%d"))
        except (ValueError, TypeError):
            continue
    if not dates:
        return {"state": "unvalidated", "days": None, "last": None,
                "models": [v.get("model", "") for v in c.validations() if v.get("model")]}
    last = max(dates)
    days = (datetime.now(timezone.utc).replace(tzinfo=None) - last).days
    state = "red" if days >= 180 else "amber" if days >= 90 else "fresh"
    models = sorted({v.get("model", "") for v in c.validations() if v.get("model")})
    return {"state": state, "days": days, "last": last.strftime("%Y-%m-%d"), "models": models}


def build_report(store: Store, canary_id: str | None = None) -> list[dict[str, Any]]:
    """Assemble the correlation data structure per canary/bomb."""
    canaries = (
        [store.get_canary(canary_id)] if canary_id else store.list_canaries()
    )
    report = []
    for c in canaries:
        if c is None:
            continue
        variants = store.list_variants(c.canary_id)
        plants = store.list_plants(c.canary_id)
        s3_hits = store.list_s3_hits(c.canary_id)
        secret_hits = store.list_secret_hits(c.canary_id)
        probe_hits = store.list_probe_hits(c.canary_id)
        report.append({
            "canary": c.to_dict(),
            "intent": c.intent,
            "variants": [v.to_dict() for v in variants],
            "plants": [p.to_dict() for p in plants],
            "s3_hits": [h.to_dict() for h in s3_hits],
            "secret_hits": [h.to_dict() for h in secret_hits],
            "probe_hits": [h.to_dict() for h in probe_hits],
            "triggered": bool(s3_hits or secret_hits or probe_hits),
            "validation": _validation_freshness(c) if c.is_deter else None,
        })
    return report


def render_text(report: list[dict[str, Any]]) -> str:
    """Render the report as a plain-text CLI view."""
    if not report:
        return "No canaries found. Create one with `canary create`.\n"

    lines: list[str] = []
    triggered_total = sum(1 for r in report if r["triggered"])
    tracers = sum(1 for r in report if r["intent"] != INTENT_DETER)
    bombs = sum(1 for r in report if r["intent"] == INTENT_DETER)
    lines.append("=" * 72)
    lines.append(f" CANARY CORRELATION REPORT   {len(report)} artefact(s): "
                 f"{tracers} tracer(s), {bombs} bomb(s), {triggered_total} TRIGGERED")
    lines.append("=" * 72)

    for r in report:
        if r["intent"] == INTENT_DETER:
            _render_bomb(lines, r)
        else:
            _render_tracer(lines, r)

    lines.append("")
    lines.append("=" * 72)
    return "\n".join(lines) + "\n"


def _render_tracer(lines: list[str], r: dict[str, Any]) -> None:
    c = r["canary"]
    mark = _STATUS_MARK.get(c["status"], c["status"])
    lines.append("")
    lines.append(f"{mark}   {c['canary_id']}   (tracer / {c['category']})")
    lines.append(f"    codename : {c['codename']}")
    lines.append(f"    quarter  : {c['quarter']}")
    lines.append(f"    created  : {c['created_at']}")
    lines.append(f"    s3 ref   : {c['s3_url'] or '(no honeytoken yet)'}")

    if r["plants"]:
        lines.append(f"    planted  : {len(r['plants'])} location(s)")
        for p in r["plants"]:
            lines.append(f"        - [{p['target_system']}] {p['location']}")
    else:
        lines.append("    planted  : (not yet planted)")

    if r["variants"]:
        lines.append(f"    variants : {len(r['variants'])}")
        for v in r["variants"]:
            lines.append(f"        - {v['variant_id']} -> audience "
                         f"'{v['audience']}'  marker: {v['marker']}")

    if r["s3_hits"]:
        lines.append(f"    S3 HITS  : {len(r['s3_hits'])}  <-- honeytoken accessed")
        for h in r["s3_hits"]:
            lines.append(f"        ! {h['event_time']}  {h['event_name']}  "
                         f"from {h['source_ip']}  UA={h['user_agent'][:60]}")
    else:
        lines.append("    S3 hits  : none")

    if r["probe_hits"]:
        lines.append(f"    PROBE HITS: {len(r['probe_hits'])}  <-- surfaced by public AI")
        for h in r["probe_hits"]:
            lines.append(f"        ! {h['probed_at']}  tool={h['tool']}  "
                         f"kind={h['probe_kind']}  token='{h['matched_token']}'  "
                         f"score={h['match_score']:.0f}")
    else:
        lines.append("    Probe hit: none")


def _render_bomb(lines: list[str], r: dict[str, Any]) -> None:
    c = r["canary"]
    mark = _STATUS_MARK.get(c["status"], c["status"])
    val = r.get("validation") or {}
    if val.get("state") == "unvalidated":
        vtxt = "UNVALIDATED (unproven control)"
    else:
        models = ", ".join(val.get("models") or []) or "?"
        vtxt = (f"validated {val.get('last')} ({val.get('days')}d ago) against "
                f"{models}  [{val.get('state')}]")
    lines.append("")
    lines.append(f"{mark}   {c['canary_id']}   (context bomb / {c.get('shape') or '?'})")
    lines.append(f"    label     : {c['codename']}")
    lines.append(f"    created   : {c['created_at']}")
    lines.append(f"    payload   : {c.get('payload_source') or '?'}")
    lines.append(f"    guardrail : {c.get('guardrail_dependency') or '(not recorded)'}")
    lines.append(f"    validation: {vtxt}")
    lines.append(f"    secret ref: {c['s3_url'] or '(no secret created yet)'}")

    if r["plants"]:
        lines.append(f"    planted   : {len(r['plants'])} location(s)")
        for p in r["plants"]:
            lines.append(f"        - [{p['target_system']}] {p['location']}")
    else:
        lines.append("    planted   : (not yet planted)")

    if r["variants"]:
        lines.append(f"    assets    : {len(r['variants'])}")
        for v in r["variants"]:
            lines.append(f"        - {v['variant_id']} -> asset '{v['audience']}'")

    if r["secret_hits"]:
        lines.append(f"    READS     : {len(r['secret_hits'])}  <-- context bomb read")
        for h in r["secret_hits"]:
            lines.append(f"        ! {h['event_time']}  {h['event_name']}  "
                         f"from {h['source_ip']}  UA={h['user_agent'][:60]}")
        lines.append("      (a read is a tripwire; whether the agent refused is inferred, not measured)")
    else:
        lines.append("    reads     : none")


def render_json(report: list[dict[str, Any]]) -> str:
    return json.dumps(report, indent=2)
