"""AWS S3 honeytoken + alerting (component 3).

honeytoken.py  - create a uniquely-named bucket/key per canary, upload a
                 harmless placeholder file, return the s3:// URL.
provision.py   - idempotent boto3 provisioner for the shared alerting
                 infrastructure: SNS topic, CloudTrail data-event logging,
                 EventBridge rule, and the alerter Lambda.
lambda_handler - the function deployed to Lambda by provision.py.
ingest.py      - pull access events back from an SQS queue (subscribed to the
                 SNS topic) into the local store, so the dashboard shows hits.
"""
