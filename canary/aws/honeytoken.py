"""Per-canary S3 honeytoken object creation.

Creates a uniquely-named bucket (or reuses a shared one) and a per-canary key,
uploads a harmless placeholder file, and returns the s3:// URL to embed in the
canary fact. The key embeds the canary_id so the Lambda maps a hit back to a
canary with no lookup table:

    <key_prefix>/<canary_id>/<random>.pdf

Object-level access logging for these buckets is set up once by provision.py
(CloudTrail data events + EventBridge). This module only creates objects.
"""

from __future__ import annotations

import uuid
from pathlib import Path
from typing import Any

import boto3
from botocore.exceptions import ClientError

from ..logging_setup import get_logger

log = get_logger()


class HoneytokenError(Exception):
    pass


class HoneytokenManager:
    def __init__(self, aws_config: dict[str, Any]):
        self.cfg = aws_config
        self.region = aws_config.get("region", "us-east-1")
        self.bucket_prefix = aws_config.get("bucket_prefix", "internal-canary")
        self.key_prefix = aws_config.get("key_prefix", "reports").strip("/")
        self.placeholder_file = aws_config.get("placeholder_file")
        self._s3 = boto3.client("s3", region_name=self.region)

    # --- bucket ----------------------------------------------------------
    def ensure_bucket(self, bucket_name: str | None = None) -> str:
        """Ensure a honeytoken bucket exists. If no name is given, a globally
        unique one is derived from the prefix + random suffix. Returns the
        bucket name. Idempotent."""
        name = bucket_name or f"{self.bucket_prefix}-{uuid.uuid4().hex[:10]}"
        try:
            if self.region == "us-east-1":
                # us-east-1 rejects a LocationConstraint.
                self._s3.create_bucket(Bucket=name)
            else:
                self._s3.create_bucket(
                    Bucket=name,
                    CreateBucketConfiguration={"LocationConstraint": self.region},
                )
            log.info("Created honeytoken bucket %s", name)
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code in ("BucketAlreadyOwnedByYou", "BucketAlreadyExists"):
                log.info("Honeytoken bucket %s already exists, reusing", name)
            else:
                raise HoneytokenError(f"Could not create bucket {name}: {exc}") from exc

        # Lock the bucket down: block all public access. A honeytoken must not
        # be genuinely reachable by the public - only insiders/scrapers with
        # access to the planted reference should ever touch it.
        try:
            self._s3.put_public_access_block(
                Bucket=name,
                PublicAccessBlockConfiguration={
                    "BlockPublicAcls": True,
                    "IgnorePublicAcls": True,
                    "BlockPublicPolicy": True,
                    "RestrictPublicBuckets": True,
                },
            )
        except ClientError as exc:  # pragma: no cover - permission dependent
            log.warning("Could not set public access block on %s: %s", name, exc)
        return name

    # --- object ----------------------------------------------------------
    def create_object(self, canary_id: str, bucket_name: str | None = None) -> dict[str, str]:
        """Create the honeytoken object for a canary. Returns a dict with
        bucket, key and url. Uses a shared bucket if ``bucket_name`` is given,
        otherwise creates a per-canary bucket."""
        bucket = self.ensure_bucket(bucket_name)
        key = f"{self.key_prefix}/{canary_id}/{uuid.uuid4().hex[:12]}.pdf"

        body = self._placeholder_bytes()
        try:
            self._s3.put_object(
                Bucket=bucket,
                Key=key,
                Body=body,
                ContentType="application/pdf",
                # Tag so an operator browsing the console sees what this is.
                Tagging=f"purpose=canary-honeytoken&canary_id={canary_id}",
            )
        except ClientError as exc:
            raise HoneytokenError(f"Could not upload honeytoken object: {exc}") from exc

        url = f"s3://{bucket}/{key}"
        log.info("Created honeytoken object for canary %s: %s", canary_id, url)
        return {"bucket": bucket, "key": key, "url": url}

    def _placeholder_bytes(self) -> bytes:
        """The harmless placeholder uploaded to each key. If a real placeholder
        file is configured and present, use it; otherwise generate a minimal,
        valid, content-free PDF. Never contains real data."""
        if self.placeholder_file:
            p = Path(self.placeholder_file)
            if p.exists():
                return p.read_bytes()
            log.warning("Configured placeholder %s missing; using generated stub", p)
        # Minimal valid single-page PDF, no real content.
        return (
            b"%PDF-1.4\n"
            b"1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n"
            b"2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n"
            b"3 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]>>endobj\n"
            b"xref\n0 4\n0000000000 65535 f \n"
            b"trailer<</Root 1 0 R/Size 4>>\n"
            b"startxref\n0\n%%EOF\n"
        )


class SecretHoneytokenManager:
    """Deter-mode honeytoken: a real AWS Secrets Manager secret whose value is
    the context-bomb payload. The secret NAME embeds the canary_id -

        <secret_prefix>/<canary_id>/<random>

    - exactly like the S3 key does, so the same Lambda maps a GetSecretValue
    read back to a canary with no lookup table, and the same SNS/ingest path is
    reused. This module only creates the secret; read alerting is wired once by
    provision.py (CloudTrail management events + EventBridge)."""

    def __init__(self, aws_config: dict[str, Any]):
        self.cfg = aws_config
        self.region = aws_config.get("region", "us-east-1")
        self.secret_prefix = aws_config.get("secret_prefix", "internal-canary").strip("/")
        self._sm = boto3.client("secretsmanager", region_name=self.region)

    def create_secret(self, canary_id: str, payload: str, shape: str | None = None) -> dict[str, str]:
        """Create the decoy secret for a deter canary. ``payload`` becomes the
        secret's value verbatim - it is the string a reading agent ingests.
        Returns a dict with name and arn. The name embeds the canary_id."""
        name = f"{self.secret_prefix}/{canary_id}/{uuid.uuid4().hex[:12]}"
        try:
            resp = self._sm.create_secret(
                Name=name,
                SecretString=payload,
                Description="Canary context-bomb decoy - synthetic, do not use",
                Tags=[
                    {"Key": "purpose", "Value": "canary-context-bomb"},
                    {"Key": "canary_id", "Value": canary_id},
                    {"Key": "shape", "Value": shape or "secrets_manager"},
                ],
            )
        except ClientError as exc:
            raise HoneytokenError(f"Could not create decoy secret: {exc}") from exc

        arn = resp.get("ARN", "")
        log.info("Created decoy secret for canary %s: %s", canary_id, name)
        return {"name": name, "arn": arn}
