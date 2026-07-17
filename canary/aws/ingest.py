"""Pull S3 honeytoken access events from the SQS ingest queue into the local
store, so the correlation dashboard shows S3 hits alongside probe hits.

Alerting is SNS-only (the security team attaches their own subscribers). This
ingest path is a *separate, optional* consumer: an SQS queue subscribed to the
same SNS topic, drained here into SQLite. It never sits on the alert path, so a
problem here cannot suppress an alert.

Messages are the JSON published by lambda_handler.handler, wrapped in the SNS
envelope. Ingest is idempotent (dedupe on the hit_id the Lambda sets).
"""

from __future__ import annotations

import json
from typing import Any

import boto3

from ..logging_setup import get_logger
from ..models import S3Hit, SecretHit
from ..store import Store

log = get_logger()


class HitIngestor:
    def __init__(self, aws_config: dict[str, Any], store: Store):
        self.region = aws_config.get("region", "us-east-1")
        self.queue_name = aws_config.get("ingest_queue_name")
        self.store = store
        self._sqs = boto3.client("sqs", region_name=self.region)

    def _queue_url(self) -> str:
        if not self.queue_name:
            raise RuntimeError("No ingest_queue_name configured; ingest disabled")
        return self._sqs.get_queue_url(QueueName=self.queue_name)["QueueUrl"]

    def ingest_once(self, max_messages: int = 100) -> int:
        """Drain currently-available messages. Returns the number of new hits
        recorded. Safe to run on a schedule."""
        qurl = self._queue_url()
        recorded = 0
        while True:
            resp = self._sqs.receive_message(
                QueueUrl=qurl,
                MaxNumberOfMessages=10,
                WaitTimeSeconds=1,
                VisibilityTimeout=30,
            )
            msgs = resp.get("Messages", [])
            if not msgs:
                break
            for m in msgs:
                try:
                    if self._handle(m):
                        recorded += 1
                    self._sqs.delete_message(
                        QueueUrl=qurl, ReceiptHandle=m["ReceiptHandle"]
                    )
                except Exception as exc:  # keep draining; log loudly
                    log.error("Failed to ingest message %s: %s", m.get("MessageId"), exc)
            if recorded >= max_messages:
                break
        log.info("Ingest complete: %d new S3 hit(s)", recorded)
        return recorded

    def _handle(self, message: dict[str, Any]) -> bool:
        body = json.loads(message["Body"])
        # Unwrap SNS envelope if present.
        payload = json.loads(body["Message"]) if "Message" in body else body
        alert = payload.get("alert")
        if alert == "s3_honeytoken_access":
            return self._handle_s3(payload, message)
        if alert == "secretsmanager_read":
            return self._handle_secret(payload, message)
        return False

    def _flip_triggered(self, canary_id: str) -> None:
        if canary_id and canary_id != "unknown":
            try:
                self.store.set_canary_status(canary_id, "triggered")
            except (KeyError, ValueError):
                pass

    def _handle_s3(self, payload: dict[str, Any], message: dict[str, Any]) -> bool:
        hit = S3Hit(
            hit_id=payload.get("hit_id") or message["MessageId"],
            canary_id=payload.get("canary_id", "unknown"),
            s3_bucket=payload.get("s3_bucket", ""),
            s3_key=payload.get("s3_key", ""),
            event_name=payload.get("event_name", ""),
            source_ip=payload.get("source_ip", ""),
            user_agent=payload.get("user_agent", ""),
            event_time=payload.get("event_time", ""),
            raw=json.dumps(payload),
        )
        is_new = self.store.add_s3_hit(hit)
        if is_new:
            self._flip_triggered(hit.canary_id)
        return is_new

    def _handle_secret(self, payload: dict[str, Any], message: dict[str, Any]) -> bool:
        hit = SecretHit(
            hit_id=payload.get("hit_id") or message["MessageId"],
            canary_id=payload.get("canary_id", "unknown"),
            secret_id=payload.get("secret_id", ""),
            event_name=payload.get("event_name", ""),
            source_ip=payload.get("source_ip", ""),
            user_agent=payload.get("user_agent", ""),
            event_time=payload.get("event_time", ""),
            raw=json.dumps(payload),
        )
        is_new = self.store.add_secret_hit(hit)
        if is_new:
            self._flip_triggered(hit.canary_id)
        return is_new
