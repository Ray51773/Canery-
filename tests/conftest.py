import os
import sys
from pathlib import Path

# Make the package importable when running pytest from the repo root.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# boto3 clients (imported by the Lambda handler module at load time) need a
# region even when no real AWS call is made. Set a harmless default and fake
# credentials so import and client creation never touch a real account.
os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")
os.environ.setdefault("AWS_ACCESS_KEY_ID", "testing")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "testing")
