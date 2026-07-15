"""Unit tests for the Lambda alerter, with SNS mocked."""

import json
from unittest import mock

from canary.aws import lambda_handler


def _event(key="reports/can_abc123/xyz.pdf", event_name="GetObject"):
    return {
        "detail": {
            "eventName": event_name,
            "eventTime": "2026-01-01T00:00:00Z",
            "sourceIPAddress": "203.0.113.7",
            "userAgent": "aws-cli/2.0",
            "awsRegion": "us-east-1",
            "userIdentity": {"arn": "arn:aws:iam::123:user/bob"},
            "requestParameters": {"bucketName": "canary-bucket", "key": key},
        }
    }


def test_canary_id_parsed_from_key():
    assert lambda_handler._canary_id_from_key("reports/can_abc/xyz.pdf") == "can_abc"
    assert lambda_handler._canary_id_from_key("weird") == "unknown"


def test_ignores_non_watched_events():
    res = lambda_handler.handler(_event(event_name="PutObject"), None)
    assert res["status"] == "ignored"


def test_publishes_to_sns(monkeypatch):
    published = {}

    class FakeSns:
        def publish(self, **kwargs):
            published.update(kwargs)
            return {"MessageId": "m1"}

    monkeypatch.setattr(lambda_handler, "_sns_client", lambda: FakeSns())
    monkeypatch.setenv("CANARY_SNS_TOPIC_ARN", "arn:aws:sns:us-east-1:123:topic")

    res = lambda_handler.handler(_event(), None)
    assert res["status"] == "alerted"
    assert res["canary_id"] == "can_abc123"
    msg = json.loads(published["Message"])
    assert msg["canary_id"] == "can_abc123"
    assert msg["source_ip"] == "203.0.113.7"
    assert msg["event_name"] == "GetObject"


def test_missing_topic_arn_raises(monkeypatch):
    monkeypatch.delenv("CANARY_SNS_TOPIC_ARN", raising=False)
    try:
        lambda_handler.handler(_event(), None)
        assert False, "expected RuntimeError on missing topic (no silent failure)"
    except RuntimeError:
        pass
