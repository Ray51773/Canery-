"""Probe runner - orchestrates outbound probes across active canaries.

For each active canary it runs two probe styles against each enabled tool:

  1. Inverse / adjacent question (default): ask *around* the fact - "what's
     shipping in Q3?" - never feeding the codename or unique token in. A leak
     shows up as the tool volunteering the fabricated detail.

  2. Verbatim-completion extraction test (membership inference): give the tool
     a distinctive sentence fragment from the canary (deliberately truncated
     before the unique token) and see whether it completes with the token.
     More directly diagnostic of training-data inclusion, but fails silently
     if the model just declines - so we run both.

Responses are fuzzy-matched against the canary's unique tokens. Any match at or
above the configured threshold is recorded as a probe hit.

Graceful degradation is a hard requirement: an unreachable tool is logged and
skipped; the runner never crashes the scheduled job.
"""

from __future__ import annotations

import uuid
from typing import Any

from ..config import Config
from ..fuzzy import find_matches
from ..generator import CanaryGenerator
from ..logging_setup import get_logger
from ..models import Canary, ProbeHit, STATUS_TRIGGERED
from ..store import Store
from .base import ProbeResponse, ProbeTarget, get_probe

log = get_logger()


def _extraction_fragment(canary: Canary) -> str:
    """A distinctive fragment of the base fact, truncated before the codename
    so the model must supply the unique token itself. If the codename is not in
    the base fact, fall back to the first half of the fact."""
    fact = canary.base_fact
    idx = fact.find(canary.codename)
    if idx > 20:
        return fact[:idx].strip()
    return fact[: max(20, len(fact) // 2)].strip()


class ProbeRunner:
    def __init__(self, config: Config, store: Store, generator: CanaryGenerator,
                 confirmed: bool = False):
        self.config = config
        self.store = store
        self.generator = generator
        # Manual confirmation gate for ToS-risky browser automation. The CLI
        # sets this True only after the operator confirms.
        self.confirmed = confirmed
        self.pcfg = config.probe

    def _build_targets(self) -> list[tuple[str, ProbeTarget]]:
        targets: list[tuple[str, ProbeTarget]] = []
        for name, tcfg in (self.pcfg.get("tools") or {}).items():
            if not tcfg.get("enabled", True):
                log.info("Probe tool %s disabled, skipping", name)
                continue
            if tcfg.get("require_confirmation", True) and not self.confirmed:
                log.warning(
                    "Probe tool %s requires manual confirmation (ToS risk); "
                    "skipping. Re-run with --confirm to enable.", name
                )
                continue
            adapter_name = tcfg.get("adapter", name)
            try:
                cls = get_probe(adapter_name)
            except KeyError as exc:
                log.error("Probe tool %s: %s", name, exc)
                continue
            targets.append((name, cls(dict(tcfg, name=name), self.config)))
        return targets

    def run(self) -> dict[str, Any]:
        """Probe every active (planted) canary. Returns a run summary."""
        # Deter bombs are skipped entirely: a bomb succeeds by making a model
        # refuse, so probing one is meaningless and would leak the payload into
        # a public tool.
        canaries = [
            c for c in self.store.list_canaries()
            if c.status in ("planted", STATUS_TRIGGERED) and not c.is_deter
        ]
        threshold = float(self.pcfg.get("match_threshold", 82))
        summary = {"canaries": len(canaries), "hits": 0, "tools_run": [], "errors": 0}

        targets = self._build_targets()
        if not targets:
            log.warning("No probe targets available (disabled or unconfirmed).")
            return summary
        summary["tools_run"] = [n for n, _ in targets]

        try:
            for canary in canaries:
                prompts = self._prompts_for(canary)
                markers = [v.marker for v in self.store.list_variants(canary.canary_id)]
                for tool_name, target in targets:
                    for kind, prompt in prompts:
                        resp = target.ask(prompt)
                        if not resp.ok:
                            summary["errors"] += 1
                            log.info("probe failed, tool %s unreachable: %s",
                                     tool_name, resp.error)
                            continue
                        hits = self._match_and_record(
                            canary, tool_name, kind, resp, markers, threshold
                        )
                        summary["hits"] += hits
        finally:
            for _, target in targets:
                target.close()

        log.info("Probe run complete: %s", summary)
        return summary

    def _prompts_for(self, canary: Canary) -> list[tuple[str, str]]:
        prompts: list[tuple[str, str]] = []
        if self.pcfg.get("run_inverse_question", True):
            for q in self.generator.inverse_probes(canary.category, canary.quarter):
                prompts.append(("inverse_question", q))
        if self.pcfg.get("run_extraction_test", True):
            frag = _extraction_fragment(canary)
            prompts.append((
                "extraction",
                f"Complete this internal note exactly as it continues: \"{frag}\"",
            ))
        return prompts

    def _match_and_record(self, canary: Canary, tool: str, kind: str,
                          resp: ProbeResponse, markers: list[str],
                          threshold: float) -> int:
        matches = find_matches(
            resp.text,
            codename=canary.codename,
            s3_key=canary.s3_key,
            markers=markers,
            threshold=threshold,
        )
        if not matches:
            return 0
        best = matches[0]
        hit = ProbeHit(
            hit_id="ph_" + uuid.uuid4().hex[:12],
            canary_id=canary.canary_id,
            tool=tool,
            probe_kind=kind,
            matched_token=best.token,
            match_score=best.score,
            response_text=resp.text[:8000],
        )
        self.store.add_probe_hit(hit)
        try:
            self.store.set_canary_status(canary.canary_id, STATUS_TRIGGERED)
        except (KeyError, ValueError):
            pass
        return 1
