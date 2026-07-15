"""Correlation dashboard / report (component 5).

The one view a human actually looks at. For each canary it shows: where and
when it was planted, S3 access hits, public-AI probe hits, and current status.
Clarity over cleverness: a plain, dense CLI report, plus a JSON dump for
piping into anything else.
"""

from __future__ import annotations

import json
from typing import Any

from .store import Store

# Human-readable status markers. Kept ASCII so the report is copy-paste safe.
_STATUS_MARK = {
    "created": "[ ] created",
    "planted": "[o] planted",
    "triggered": "[!] TRIGGERED",
    "retired": "[x] retired",
}


def build_report(store: Store, canary_id: str | None = None) -> list[dict[str, Any]]:
    """Assemble the correlation data structure per canary."""
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
        probe_hits = store.list_probe_hits(c.canary_id)
        report.append({
            "canary": c.to_dict(),
            "variants": [v.to_dict() for v in variants],
            "plants": [p.to_dict() for p in plants],
            "s3_hits": [h.to_dict() for h in s3_hits],
            "probe_hits": [h.to_dict() for h in probe_hits],
            "triggered": bool(s3_hits or probe_hits),
        })
    return report


def render_text(report: list[dict[str, Any]]) -> str:
    """Render the report as a plain-text CLI view."""
    if not report:
        return "No canaries found. Create one with `canary create`.\n"

    lines: list[str] = []
    triggered_total = sum(1 for r in report if r["triggered"])
    lines.append("=" * 72)
    lines.append(f" CANARY CORRELATION REPORT   {len(report)} canary(ies), "
                 f"{triggered_total} TRIGGERED")
    lines.append("=" * 72)

    for r in report:
        c = r["canary"]
        mark = _STATUS_MARK.get(c["status"], c["status"])
        lines.append("")
        lines.append(f"{mark}   {c['canary_id']}   ({c['category']})")
        lines.append(f"    codename : {c['codename']}")
        lines.append(f"    quarter  : {c['quarter']}")
        lines.append(f"    created  : {c['created_at']}")
        lines.append(f"    s3 ref   : {c['s3_url'] or '(no honeytoken yet)'}")

        # Where planted.
        if r["plants"]:
            lines.append(f"    planted  : {len(r['plants'])} location(s)")
            for p in r["plants"]:
                lines.append(f"        - [{p['target_system']}] {p['location']}")
        else:
            lines.append("    planted  : (not yet planted)")

        # Variants / audiences (barium-meal tracing).
        if r["variants"]:
            lines.append(f"    variants : {len(r['variants'])}")
            for v in r["variants"]:
                lines.append(f"        - {v['variant_id']} -> audience "
                             f"'{v['audience']}'  marker: {v['marker']}")

        # S3 hits.
        if r["s3_hits"]:
            lines.append(f"    S3 HITS  : {len(r['s3_hits'])}  <-- honeytoken accessed")
            for h in r["s3_hits"]:
                lines.append(f"        ! {h['event_time']}  {h['event_name']}  "
                             f"from {h['source_ip']}  UA={h['user_agent'][:60]}")
        else:
            lines.append("    S3 hits  : none")

        # Probe hits.
        if r["probe_hits"]:
            lines.append(f"    PROBE HITS: {len(r['probe_hits'])}  <-- surfaced by public AI")
            for h in r["probe_hits"]:
                lines.append(f"        ! {h['probed_at']}  tool={h['tool']}  "
                             f"kind={h['probe_kind']}  token='{h['matched_token']}'  "
                             f"score={h['match_score']:.0f}")
        else:
            lines.append("    Probe hit: none")

    lines.append("")
    lines.append("=" * 72)
    return "\n".join(lines) + "\n"


def render_json(report: list[dict[str, Any]]) -> str:
    return json.dumps(report, indent=2)
