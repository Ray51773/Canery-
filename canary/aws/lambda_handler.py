"""Lambda function for the S3 honeytoken alert path (component 3).

Triggered by EventBridge on object-level GetObject/HeadObject events that
CloudTrail records for the honeytoken buckets. It:

  1. Extracts timestamp, source IP, user agent, bucket and key from the event.
  2. Maps the key back to a canary_id. Keys are named
        <key_prefix>/<canary_id>/<random>.pdf
     so the mapping needs no lookup table - the canary_id is in the key.
  3. Publishes a structured alert to the configured SNS topic.

Design rule from the build spec: NO silent failures on the alerting path. If
the SNS publish fails, the exception propagates so Lambda records the error and
retries/DLQs it, rather than swallowing a missed leak signal.

This file is self-contained (stdlib + boto3, which the Lambda runtime provides)
so it can be zipped and deployed as-is by ``provision.py``.
"""

from __future__ import annotations

import json
import os
import boto3

# Watched object-level read events. HeadObject included: a scraper often HEADs
# before GETting, and either is a leak signal.
WATCHED_EVENTS = {"GetObject", "HeadObject"}
# Secrets Manager reads on a decoy secret: an agent read a context bomb.
WATCHED_SECRET_EVENTS = {"GetSecretValue", "BatchGetSecretValue"}

# The SNS client is created lazily so this module imports anywhere (tests,
# tooling) without a configured region. In the Lambda runtime AWS_REGION is
# always set, so the first call constructs the client normally.
_sns = None


def _sns_client():
    global _sns
    if _sns is None:
        _sns = boto3.client("sns")
    return _sns


def _canary_id_from_key(key: str) -> str:
    """Keys look like '<prefix>/<canary_id>/<rand>.pdf'. The canary_id is the
    path segment immediately before the filename. Returns 'unknown' if the key
    does not match the expected shape (still alerts - an access to any
    honeytoken key is worth surfacing)."""
    parts = [p for p in (key or "").split("/") if p]
    if len(parts) >= 2:
        return parts[-2]
    return "unknown"


def _canary_id_from_secret(secret_id: str) -> str:
    """Decoy secret names/ARNs look like '<prefix>/<canary_id>/<rand>' (an ARN
    appends a random '-abc123' suffix Secrets Manager adds). The canary_id is
    the second-to-last '/'-delimited segment, mirroring the S3 key mapping."""
    # An ARN is arn:aws:secretsmanager:region:acct:secret:<name>-<suffix>; take
    # the name portion after 'secret:' if present, then apply the key logic.
    name = secret_id
    if ":secret:" in secret_id:
        name = secret_id.split(":secret:", 1)[1]
    parts = [p for p in (name or "").split("/") if p]
    if len(parts) >= 2:
        return parts[-2]
    return "unknown"


def _extract(detail: dict) -> dict:
    req = detail.get("requestParameters", {}) or {}
    bucket = req.get("bucketName", "")
    key = req.get("key", "")
    return {
        "event_name": detail.get("eventName", ""),
        "event_time": detail.get("eventTime", ""),
        "source_ip": detail.get("sourceIPAddress", ""),
        "user_agent": detail.get("userAgent", ""),
        "bucket": bucket,
        "key": key,
        "canary_id": _canary_id_from_key(key),
        "aws_region": detail.get("awsRegion", ""),
        # readOnly / principal help triage a hit.
        "principal": (detail.get("userIdentity", {}) or {}).get("arn", ""),
    }


def _extract_secret(detail: dict) -> dict:
    req = detail.get("requestParameters", {}) or {}
    secret_id = req.get("secretId", "") or ""
    return {
        "event_name": detail.get("eventName", ""),
        "event_time": detail.get("eventTime", ""),
        "source_ip": detail.get("sourceIPAddress", ""),
        "user_agent": detail.get("userAgent", ""),
        "secret_id": secret_id,
        "canary_id": _canary_id_from_secret(secret_id),
        "aws_region": detail.get("awsRegion", ""),
        "principal": (detail.get("userIdentity", {}) or {}).get("arn", ""),
    }


def _publish(topic_arn: str, subject: str, message: dict, alert_type: str) -> None:
    print(json.dumps({"publishing": message}))
    _sns_client().publish(
        TopicArn=topic_arn,
        Subject=subject,
        Message=json.dumps(message, indent=2),
        MessageAttributes={
            "canary_id": {"DataType": "String", "StringValue": message.get("canary_id") or "unknown"},
            "alert_type": {"DataType": "String", "StringValue": alert_type},
        },
    )


def handler(event, context):  # noqa: ANN001 - Lambda signature
    """EventBridge -> Lambda entry point. Handles both S3 object reads (tracer
    honeytokens) and Secrets Manager reads (deter context bombs), publishing a
    structured alert to the same SNS topic for either."""
    detail = event.get("detail", {}) if isinstance(event, dict) else {}
    event_name = detail.get("eventName", "")
    event_source = detail.get("eventSource", "")

    topic_arn = os.environ.get("CANARY_SNS_TOPIC_ARN", "")

    # --- Secrets Manager read (deter) ---
    if event_source == "secretsmanager.amazonaws.com" or event_name in WATCHED_SECRET_EVENTS:
        if event_name not in WATCHED_SECRET_EVENTS:
            print(json.dumps({"skipped": True, "event_name": event_name}))
            return {"status": "ignored", "event_name": event_name}
        if not topic_arn:
            raise RuntimeError("CANARY_SNS_TOPIC_ARN not set; cannot publish alert")
        info = _extract_secret(detail)
        subject = f"[CANARY] context bomb read: {info['canary_id']}"[:100]
        message = {
            "alert": "secretsmanager_read",
            "canary_id": info["canary_id"],
            "secret_id": info["secret_id"],
            "event_name": info["event_name"],
            "event_time": info["event_time"],
            "source_ip": info["source_ip"],
            "user_agent": info["user_agent"],
            "principal": info["principal"],
            "aws_region": info["aws_region"],
        }
        message["hit_id"] = f"{info['secret_id']}::{info['event_time']}::{info['source_ip']}"
        _publish(topic_arn, subject, message, "secretsmanager_read")
        return {"status": "alerted", "canary_id": info["canary_id"], "alert": "secretsmanager_read"}

    # --- S3 object read (tracer) ---
    if event_name not in WATCHED_EVENTS:
        # EventBridge should already filter, but double-check so noise never
        # pages the security team.
        print(json.dumps({"skipped": True, "event_name": event_name}))
        return {"status": "ignored", "event_name": event_name}

    info = _extract(detail)
    if not topic_arn:
        # Misconfiguration on the alert path must be loud, not silent.
        raise RuntimeError("CANARY_SNS_TOPIC_ARN not set; cannot publish alert")

    subject = f"[CANARY] S3 honeytoken accessed: {info['canary_id']}"[:100]
    message = {
        "alert": "s3_honeytoken_access",
        "canary_id": info["canary_id"],
        "s3_bucket": info["bucket"],
        "s3_key": info["key"],
        "event_name": info["event_name"],
        "event_time": info["event_time"],
        "source_ip": info["source_ip"],
        "user_agent": info["user_agent"],
        "principal": info["principal"],
        "aws_region": info["aws_region"],
    }

    # A structured hit_id lets downstream ingest dedupe an at-least-once queue.
    message["hit_id"] = f"{info['key']}::{info['event_time']}::{info['source_ip']}"

    _publish(topic_arn, subject, message, "s3_honeytoken_access")
    return {"status": "alerted", "canary_id": info["canary_id"]}
