"""Idempotent boto3 provisioner for the S3 honeytoken alerting infrastructure.

Wires up, in one account the security team owns:

    honeytoken buckets  --(object-level data events)-->  CloudTrail
    CloudTrail          --(GetObject/HeadObject)------->  EventBridge rule
    EventBridge rule    ------------------------------->  alerter Lambda
    alerter Lambda      ------------------------------->  SNS topic (alerts)
    SNS topic           --(optional)------------------->  SQS ingest queue

Design note on reuse: the build spec suggests reusing Canarytokens' own AWS
canary generation. Canarytokens' hosted AWS token mints an IAM access key whose
use shows up in a *shared, Thinkst-operated* CloudTrail. Here the security team
owns the account and wants object-level GetObject/HeadObject on their own S3
keys, feeding their own alerting - so we provision CloudTrail data events +
EventBridge directly. It is a small amount of well-understood wiring, fully
auditable, with no third-party dependency in the alert path. The Canarytokens
*fuzzy/token* ideas are reused conceptually (unique per-token identifiers, an
inert placeholder object); the AWS control plane is our own.

Every step is idempotent: re-running reconciles rather than duplicating. All
actions log to the central logger.
"""

from __future__ import annotations

import io
import json
import time
import uuid
import zipfile
from pathlib import Path
from typing import Any

import boto3
from botocore.exceptions import ClientError

from ..logging_setup import get_logger

log = get_logger()

LAMBDA_RUNTIME = "python3.11"
LAMBDA_HANDLER = "lambda_handler.handler"


class ProvisionError(Exception):
    pass


class Provisioner:
    def __init__(self, aws_config: dict[str, Any]):
        self.cfg = aws_config
        self.region = aws_config.get("region", "us-east-1")
        self._sns = boto3.client("sns", region_name=self.region)
        self._iam = boto3.client("iam", region_name=self.region)
        self._lambda = boto3.client("lambda", region_name=self.region)
        self._events = boto3.client("events", region_name=self.region)
        self._ct = boto3.client("cloudtrail", region_name=self.region)
        self._s3 = boto3.client("s3", region_name=self.region)
        self._sqs = boto3.client("sqs", region_name=self.region)
        self._sts = boto3.client("sts", region_name=self.region)

    # -- account id -------------------------------------------------------
    def _account_id(self) -> str:
        return self._sts.get_caller_identity()["Account"]

    # -- SNS --------------------------------------------------------------
    def ensure_sns_topic(self) -> str:
        name = self.cfg.get("sns_topic_name", "canary-honeytoken-alerts")
        resp = self._sns.create_topic(Name=name)  # create_topic is idempotent
        arn = resp["TopicArn"]
        log.info("SNS topic ready: %s", arn)
        return arn

    # -- IAM role for Lambda ---------------------------------------------
    def ensure_lambda_role(self, sns_topic_arn: str) -> str:
        role_name = self.cfg.get("lambda_role_name", "canary-alerter-role")
        assume = {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }],
        }
        try:
            role = self._iam.create_role(
                RoleName=role_name,
                AssumeRolePolicyDocument=json.dumps(assume),
                Description="Canary honeytoken alerter Lambda execution role",
            )
            arn = role["Role"]["Arn"]
            log.info("Created IAM role %s", role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "EntityAlreadyExists":
                arn = self._iam.get_role(RoleName=role_name)["Role"]["Arn"]
                log.info("IAM role %s already exists", role_name)
            else:
                raise ProvisionError(f"Could not create role {role_name}: {exc}") from exc

        # Basic execution (CloudWatch Logs) + publish to the alert topic only.
        self._iam.attach_role_policy(
            RoleName=role_name,
            PolicyArn="arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole",
        )
        self._iam.put_role_policy(
            RoleName=role_name,
            PolicyName="canary-sns-publish",
            PolicyDocument=json.dumps({
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Action": "sns:Publish",
                    "Resource": sns_topic_arn,
                }],
            }),
        )
        return arn

    # -- Lambda -----------------------------------------------------------
    def _lambda_zip(self) -> bytes:
        """Zip the handler source. The handler is self-contained (stdlib +
        boto3, which the runtime provides)."""
        handler_src = Path(__file__).with_name("lambda_handler.py").read_text(encoding="utf-8")
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("lambda_handler.py", handler_src)
        return buf.getvalue()

    def ensure_lambda(self, role_arn: str, sns_topic_arn: str) -> str:
        fn_name = self.cfg.get("lambda_function_name", "canary-honeytoken-alerter")
        code = self._lambda_zip()
        env = {"Variables": {"CANARY_SNS_TOPIC_ARN": sns_topic_arn}}

        try:
            resp = self._create_lambda_with_retry(fn_name, role_arn, code, env)
            arn = resp["FunctionArn"]
            log.info("Created Lambda %s", fn_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceConflictException":
                self._lambda.update_function_code(FunctionName=fn_name, ZipFile=code)
                self._wait_lambda_updated(fn_name)
                self._lambda.update_function_configuration(
                    FunctionName=fn_name, Environment=env, Handler=LAMBDA_HANDLER,
                    Runtime=LAMBDA_RUNTIME, Role=role_arn,
                )
                arn = self._lambda.get_function(FunctionName=fn_name)["Configuration"]["FunctionArn"]
                log.info("Updated existing Lambda %s", fn_name)
            else:
                raise ProvisionError(f"Could not create Lambda {fn_name}: {exc}") from exc
        return arn

    def _create_lambda_with_retry(self, fn_name, role_arn, code, env, attempts=6):
        """A freshly created IAM role is not immediately assumable; retry the
        create on the transient 'cannot be assumed' error."""
        last = None
        for i in range(attempts):
            try:
                return self._lambda.create_function(
                    FunctionName=fn_name,
                    Runtime=LAMBDA_RUNTIME,
                    Role=role_arn,
                    Handler=LAMBDA_HANDLER,
                    Code={"ZipFile": code},
                    Timeout=30,
                    MemorySize=128,
                    Environment=env,
                    Description="Canary S3 honeytoken -> SNS alerter",
                )
            except ClientError as exc:
                msg = exc.response["Error"].get("Message", "")
                if exc.response["Error"]["Code"] == "InvalidParameterValueException" and "assume" in msg:
                    last = exc
                    time.sleep(2 * (i + 1))
                    continue
                raise
        raise ProvisionError(f"Lambda role not assumable after retries: {last}")

    def _wait_lambda_updated(self, fn_name: str) -> None:
        waiter = self._lambda.get_waiter("function_updated")
        waiter.wait(FunctionName=fn_name)

    # -- EventBridge ------------------------------------------------------
    def ensure_eventbridge(self, lambda_arn: str) -> str:
        rule_name = self.cfg.get("eventbridge_rule_name", "canary-s3-data-access")
        # Match CloudTrail-delivered S3 data events for read operations.
        pattern = {
            "source": ["aws.s3"],
            "detail-type": ["AWS API Call via CloudTrail"],
            "detail": {
                "eventSource": ["s3.amazonaws.com"],
                "eventName": ["GetObject", "HeadObject"],
            },
        }
        self._events.put_rule(
            Name=rule_name,
            EventPattern=json.dumps(pattern),
            State="ENABLED",
            Description="Canary: S3 object-level read on honeytoken keys",
        )
        self._events.put_targets(
            Rule=rule_name,
            Targets=[{"Id": "canary-alerter", "Arn": lambda_arn}],
        )
        # Allow EventBridge to invoke the Lambda (idempotent add_permission).
        fn_name = self.cfg.get("lambda_function_name", "canary-honeytoken-alerter")
        rule_arn = self._events.describe_rule(Name=rule_name)["Arn"]
        try:
            self._lambda.add_permission(
                FunctionName=fn_name,
                StatementId="canary-eventbridge-invoke",
                Action="lambda:InvokeFunction",
                Principal="events.amazonaws.com",
                SourceArn=rule_arn,
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceConflictException":
                raise
        log.info("EventBridge rule ready: %s", rule_name)
        return rule_arn

    # -- EventBridge: Secrets Manager reads (deter mode) -----------------
    def ensure_secretsmanager_eventbridge(self, lambda_arn: str) -> str:
        """Route Secrets Manager read events (GetSecretValue) on decoy secrets
        to the same alerter Lambda. GetSecretValue is a CloudTrail management
        event, delivered to EventBridge as an 'AWS API Call via CloudTrail'
        without needing data-event selectors - so this is a second rule onto
        the same Lambda/SNS path, not a second stack."""
        rule_name = self.cfg.get("secretsmanager_rule_name", "canary-secretsmanager-read")
        pattern = {
            "source": ["aws.secretsmanager"],
            "detail-type": ["AWS API Call via CloudTrail"],
            "detail": {
                "eventSource": ["secretsmanager.amazonaws.com"],
                "eventName": ["GetSecretValue", "BatchGetSecretValue"],
            },
        }
        self._events.put_rule(
            Name=rule_name,
            EventPattern=json.dumps(pattern),
            State="ENABLED",
            Description="Canary: Secrets Manager read on context-bomb decoy secrets",
        )
        self._events.put_targets(
            Rule=rule_name,
            Targets=[{"Id": "canary-alerter", "Arn": lambda_arn}],
        )
        fn_name = self.cfg.get("lambda_function_name", "canary-honeytoken-alerter")
        rule_arn = self._events.describe_rule(Name=rule_name)["Arn"]
        try:
            self._lambda.add_permission(
                FunctionName=fn_name,
                StatementId="canary-eventbridge-invoke-secrets",
                Action="lambda:InvokeFunction",
                Principal="events.amazonaws.com",
                SourceArn=rule_arn,
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceConflictException":
                raise
        log.info("EventBridge rule ready (Secrets Manager): %s", rule_name)
        return rule_arn

    # -- CloudTrail data events ------------------------------------------
    def ensure_cloudtrail(self, honeytoken_buckets: list[str]) -> str:
        """Ensure a trail exists with S3 data-event selectors for the given
        honeytoken buckets. CloudTrail delivers these data events to
        EventBridge, which drives the alert. Idempotent; extends selectors to
        cover any new buckets."""
        trail_name = self.cfg.get("cloudtrail_name", "canary-data-events")
        log_bucket = self._ensure_cloudtrail_log_bucket()

        try:
            self._ct.create_trail(
                Name=trail_name,
                S3BucketName=log_bucket,
                IsMultiRegionTrail=True,
                IncludeGlobalServiceEvents=True,
            )
            log.info("Created CloudTrail trail %s", trail_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "TrailAlreadyExistsException":
                log.info("CloudTrail trail %s already exists", trail_name)
            else:
                raise ProvisionError(f"Could not create trail {trail_name}: {exc}") from exc

        # Advanced event selector: S3 GetObject/HeadObject on the honeytoken
        # bucket ARNs only, to keep data-event volume (and cost) minimal.
        resources = [f"arn:aws:s3:::{b}/" for b in honeytoken_buckets]
        selectors = [{
            "Name": "canary-honeytoken-reads",
            "FieldSelectors": [
                {"Field": "eventCategory", "Equals": ["Data"]},
                {"Field": "resources.type", "Equals": ["AWS::S3::Object"]},
                {"Field": "resources.ARN", "StartsWith": resources} if resources else
                {"Field": "resources.type", "Equals": ["AWS::S3::Object"]},
            ],
        }]
        self._ct.put_event_selectors(
            TrailName=trail_name,
            AdvancedEventSelectors=selectors,
        )
        try:
            self._ct.start_logging(Name=trail_name)
        except ClientError as exc:  # pragma: no cover
            log.warning("Could not start logging on %s: %s", trail_name, exc)
        log.info("CloudTrail data events configured for %d bucket(s)", len(honeytoken_buckets))
        return trail_name

    def _ensure_cloudtrail_log_bucket(self) -> str:
        prefix = self.cfg.get("cloudtrail_log_bucket_prefix", "canary-cloudtrail-logs")
        account = self._account_id()
        # Deterministic name so re-runs reuse the same log bucket.
        name = f"{prefix}-{account}-{self.region}"
        try:
            if self.region == "us-east-1":
                self._s3.create_bucket(Bucket=name)
            else:
                self._s3.create_bucket(
                    Bucket=name,
                    CreateBucketConfiguration={"LocationConstraint": self.region},
                )
            log.info("Created CloudTrail log bucket %s", name)
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code not in ("BucketAlreadyOwnedByYou", "BucketAlreadyExists"):
                raise ProvisionError(f"Could not create log bucket {name}: {exc}") from exc

        # CloudTrail needs an explicit bucket policy to write logs.
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "AWSCloudTrailAclCheck",
                    "Effect": "Allow",
                    "Principal": {"Service": "cloudtrail.amazonaws.com"},
                    "Action": "s3:GetBucketAcl",
                    "Resource": f"arn:aws:s3:::{name}",
                },
                {
                    "Sid": "AWSCloudTrailWrite",
                    "Effect": "Allow",
                    "Principal": {"Service": "cloudtrail.amazonaws.com"},
                    "Action": "s3:PutObject",
                    "Resource": f"arn:aws:s3:::{name}/AWSLogs/{account}/*",
                    "Condition": {"StringEquals": {"s3:x-amz-acl": "bucket-owner-full-control"}},
                },
            ],
        }
        self._s3.put_bucket_policy(Bucket=name, Policy=json.dumps(policy))
        return name

    # -- optional SQS ingest queue ---------------------------------------
    def ensure_ingest_queue(self, sns_topic_arn: str) -> str | None:
        """Create an SQS queue subscribed to the alert SNS topic so
        `canary ingest-hits` can pull access events into the local DB for the
        dashboard. Returns the queue URL, or None if not configured."""
        qname = self.cfg.get("ingest_queue_name")
        if not qname:
            return None
        q = self._sqs.create_queue(QueueName=qname)
        qurl = q["QueueUrl"]
        attrs = self._sqs.get_queue_attributes(
            QueueUrl=qurl, AttributeNames=["QueueArn"]
        )["Attributes"]
        qarn = attrs["QueueArn"]

        # Allow the SNS topic to send to this queue.
        policy = {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"Service": "sns.amazonaws.com"},
                "Action": "sqs:SendMessage",
                "Resource": qarn,
                "Condition": {"ArnEquals": {"aws:SourceArn": sns_topic_arn}},
            }],
        }
        self._sqs.set_queue_attributes(
            QueueUrl=qurl, Attributes={"Policy": json.dumps(policy)}
        )
        self._sns.subscribe(
            TopicArn=sns_topic_arn, Protocol="sqs", Endpoint=qarn,
            Attributes={"RawMessageDelivery": "false"},
        )
        log.info("Ingest queue ready and subscribed: %s", qurl)
        return qurl

    # -- orchestration ----------------------------------------------------
    def provision_all(self, honeytoken_buckets: list[str]) -> dict[str, str]:
        """Provision the whole alerting stack. Safe to re-run. ``honeytoken_
        buckets`` is the set of buckets whose object reads should alert."""
        out: dict[str, str] = {}
        out["sns_topic_arn"] = self.ensure_sns_topic()
        out["lambda_role_arn"] = self.ensure_lambda_role(out["sns_topic_arn"])
        out["lambda_arn"] = self.ensure_lambda(out["lambda_role_arn"], out["sns_topic_arn"])
        out["eventbridge_rule_arn"] = self.ensure_eventbridge(out["lambda_arn"])
        out["secretsmanager_rule_arn"] = self.ensure_secretsmanager_eventbridge(out["lambda_arn"])
        out["cloudtrail_name"] = self.ensure_cloudtrail(honeytoken_buckets)
        qurl = self.ensure_ingest_queue(out["sns_topic_arn"])
        if qurl:
            out["ingest_queue_url"] = qurl
        log.info("Provisioning complete: %s", json.dumps(out, indent=2))
        return out
