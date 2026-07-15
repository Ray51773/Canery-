"""Confluence injection adapter - the configured production target.

Creates one Confluence page per variant under a configured space (and optional
parent page) using the Confluence Cloud REST API. Credentials are read from the
environment, never from config:

    CANARY_CONFLUENCE_USER   - Atlassian account email
    CANARY_CONFLUENCE_TOKEN  - Atlassian API token (id.atlassian.com -> API tokens)

The page body is plain, believable internal documentation so a human or an AI
agent with read access has no reason to doubt it. Each variant is a separate
page, giving a retrieval index several paraphrases to match and keeping each
variant traceable to its audience.

This adapter talks to a real external system. It is written to fail loudly:
any non-2xx response raises, so the caller does not record a plant that did not
happen.
"""

from __future__ import annotations

from typing import Any

import requests

from ..logging_setup import get_logger
from ..models import Canary, Variant
from .base import PlantResult, TargetAdapter, register_adapter

log = get_logger()


@register_adapter("confluence")
class ConfluenceAdapter(TargetAdapter):
    def __init__(self, target_config: dict[str, Any], global_config: Any = None):
        super().__init__(target_config, global_config)
        self.base_url = target_config.get("base_url", "").rstrip("/")
        self.space_key = target_config.get("space_key")
        self.parent_page_id = target_config.get("parent_page_id")
        self.timeout = int(target_config.get("timeout_seconds", 30))

        if not self.base_url or not self.space_key:
            raise ValueError(
                "Confluence adapter needs base_url and space_key in its config block"
            )

        # Secrets from the environment only.
        user_env = target_config.get("username_env", "CANARY_CONFLUENCE_USER")
        token_env = target_config.get("token_env", "CANARY_CONFLUENCE_TOKEN")
        self.username = self._env(global_config, user_env)
        self.token = self._env(global_config, token_env)
        if not self.username or not self.token:
            raise ValueError(
                f"Confluence credentials missing: set {user_env} and {token_env} "
                f"in the environment"
            )

    @staticmethod
    def _env(global_config: Any, name: str) -> str | None:
        if global_config is not None and hasattr(global_config, "env"):
            return global_config.env(name)
        import os
        return os.environ.get(name)

    def plant(self, canary: Canary, variants: list[Variant]) -> list[PlantResult]:
        results: list[PlantResult] = []
        session = requests.Session()
        session.auth = (self.username, self.token)
        session.headers.update({"Content-Type": "application/json"})

        for v in variants:
            title = f"{canary.codename} - {canary.category} note ({v.variant_id})"
            page = self._create_page(session, title, canary, v)
            page_id = page.get("id")
            # Build a human-facing URL when the API returns a webui link.
            webui = (page.get("_links", {}) or {}).get("webui", "")
            url = f"{self.base_url}{webui}" if webui else f"{self.base_url}/pages/{page_id}"
            log.info("Planted variant %s -> Confluence page %s", v.variant_id, page_id)
            results.append(
                PlantResult(
                    variant_id=v.variant_id,
                    location=url,
                    detail={"page_id": page_id, "audience": v.audience, "title": title},
                )
            )
        return results

    def _create_page(
        self, session: requests.Session, title: str, canary: Canary, v: Variant
    ) -> dict[str, Any]:
        body_html = (
            f"<p><em>Audience: {v.audience}</em></p>"
            f"<p>{v.text}</p>"
            f"<p>Source of record: <code>{canary.s3_url}</code></p>"
        )
        payload: dict[str, Any] = {
            "type": "page",
            "title": title,
            "space": {"key": self.space_key},
            "body": {"storage": {"value": body_html, "representation": "storage"}},
        }
        if self.parent_page_id:
            payload["ancestors"] = [{"id": str(self.parent_page_id)}]

        resp = session.post(
            f"{self.base_url}/rest/api/content",
            json=payload,
            timeout=self.timeout,
        )
        if resp.status_code >= 300:
            # Fail loudly - never silently drop a plant.
            log.error(
                "Confluence page creation failed (%s): %s",
                resp.status_code, resp.text[:500],
            )
            resp.raise_for_status()
        return resp.json()
