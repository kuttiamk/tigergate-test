# =============================================================================
# secrets/secrets_all_formats.py – TigerGate CNAPP: Secrets Detection
# =============================================================================
# PURPOSE: A single Python file containing 20+ secret formats covering every
# major secrets scanning pattern. Designed to trigger TruffleHog, Gitleaks,
# GitGuardian, and TigerGate Secrets Detection.
#
# SECRET CATEGORIES:
#   CAT-01: AWS (Access Keys, Secret Keys, Session Tokens)
#   CAT-02: GCP (Service Account JSON, API Keys)
#   CAT-03: Azure (Connection Strings, Service Principal, SAS Tokens)
#   CAT-04: GitHub (Personal Access Tokens, OAuth, App Tokens)
#   CAT-05: Database (PostgreSQL, MySQL, MongoDB, Redis)
#   CAT-06: Payment (Stripe, PayPal, Braintree)
#   CAT-07: Messaging (Slack, Twilio, SendGrid)
#   CAT-08: TLS/Crypto (RSA Private Key, PEM)
#   CAT-09: JWT Tokens (hardcoded signing keys)
#   CAT-10: API Keys (generic high-entropy strings)
# =============================================================================

# ── CAT-01: AWS Credentials ──────────────────────────────────────────────────
# 🔴 VULN: CWE-798 – Hardcoded AWS Access Key
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
AWS_SESSION_TOKEN = "AQoXnyc4lcK4w4OIaYnuFgZNUiZii/EVnWn7LLDjOwLhJFbE+heXtqtRTRFQhYRnl8k="

# ── CAT-02: GCP Service Account ──────────────────────────────────────────────
# 🔴 VULN: GCP Service Account JSON inline
GCP_SERVICE_ACCOUNT = {
  "type": "service_account",
  "project_id": "megacorp-prod-334891",
  "private_key_id": "a27b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b",
  "private_key": "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA2a2rwplBQLzHPZe5TYZJPQ...(TRUNCATED FOR DEMO)\n-----END RSA PRIVATE KEY-----\n",
  "client_email": "deployer@megacorp-prod-334891.iam.gserviceaccount.com",
  "client_id": "103456789012345678901",
  "auth_uri": "https://accounts.google.com/o/oauth2/auth",
  "token_uri": "https://oauth2.googleapis.com/token"
}
GCP_API_KEY = "AIzaSyDdI0hCZtE6vFgrxSyM3bRaL22RXmtFMiw"  # 🔴 VULN: GCP API Key

# ── CAT-03: Azure Credentials ────────────────────────────────────────────────
# 🔴 VULN: Azure Storage Connection String
AZURE_STORAGE_CONNECTION_STRING = "DefaultEndpointsProtocol=https;AccountName=megacorpstorage;AccountKey=dGhpcyBpcyBhIGZha2UgYmFzZTY0IGtleSBmb3IgdGVzdGluZyBvbmx5IHdoaWNoIGlzIHNlY3JldA==;EndpointSuffix=core.windows.net"

# 🔴 VULN: Azure Service Principal
AZURE_CLIENT_ID = "12345678-1234-1234-1234-123456789012"
AZURE_CLIENT_SECRET = "~abcDEFghiJKL123456789mno~PQRSTU"
AZURE_TENANT_ID = "abcDefgh-1234-5678-abcd-efghijklmnop"

# 🔴 VULN: Azure SAS Token
AZURE_SAS_TOKEN = "sv=2020-08-04&ss=b&srt=sco&sp=rwdlacupitfx&se=2026-12-31T00:00:00Z&st=2026-01-01T00:00:00Z&spr=https&sig=EXAMPLE_SIGNATURE_VALUE_NOT_REAL"

# ── CAT-04: GitHub Tokens ────────────────────────────────────────────────────
# 🔴 VULN: GitHub Personal Access Token (classic)
GITHUB_TOKEN = "ghp_1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f"  # 🔴 VULN: GitHub PAT
# 🔴 VULN: GitHub App Private Key marker
GITHUB_APP_PRIVATE_KEY = "-----BEGIN RSA PRIVATE KEY-----\n...GITHUB_APP_KEY...\n-----END RSA PRIVATE KEY-----"

# ── CAT-05: Database Credentials ─────────────────────────────────────────────
# 🔴 VULN: PostgreSQL connection URLs
POSTGRES_URL = "postgresql://admin:SuperSecret123@prod-db.internal.megacorp.com:5432/megacorp_prod"
MYSQL_URL = "mysql://root:RootPass123!@megacorp-mysql.us-east-1.rds.amazonaws.com:3306/prod"
MONGODB_URL = "mongodb+srv://dbadmin:MongoDB@tlsSecret!@cluster0.megacorp.mongodb.net/production"
REDIS_URL = "redis://:RedisP@ssw0rd@megacorp-cache.abc123.cache.amazonaws.com:6379/0"

# ── CAT-06: Payment Keys ──────────────────────────────────────────────────────
# 🔴 VULN: Stripe Live API Key (pattern: sk_live_xxxx)
STRIPE_SECRET_KEY = "STRIPE_LIVE_EXAMPLE_TEST_KEY_NOT_REAL"  # 🔴 VULN: Stripe Live Key pattern
STRIPE_WEBHOOK_SECRET = "whsec_1234567890abcdefghijklmnopqrstuvwxyz"
PAYPAL_CLIENT_SECRET = "EK5pKAeVYiDAVu4dD_Ux9U8sXeTj7A-3kNm84OmVVmHw8wFpE_V4tI8D"
BRAINTREE_PRIVATE_KEY = "b2a61e9e35b08ffa9cc27f2bfb8440a5"

# ── CAT-07: Messaging & Communication ─────────────────────────────────────────
# 🔴 VULN: Slack Bot Token
SLACK_BOT_TOKEN = "xoxb-EXAMPLE-2345678901-2345678901234-ABCDEFghijklmnopqrstuvwx"  # 🔴 VULN: Slack Bot Token
SLACK_WEBHOOK = "https://hooks.slack.com/services/T0EXAMPLE/B01GHIJKL/AbCdEfGhIjKlMnOpQrStUvWxFAKE"  # 🔴 VULN: Slack Webhook

# 🔴 VULN: Twilio credentials
TWILIO_ACCOUNT_SID = "AC-EXAMPLE-a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4"  # 🔴 VULN: Twilio SID pattern
TWILIO_AUTH_TOKEN = "1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d"

# 🔴 VULN: SendGrid API Key
SENDGRID_API_KEY = "SG.A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0U1v2W3x4Y5z6A7b8"

# ── CAT-08: TLS / Cryptographic Keys ─────────────────────────────────────────
# 🔴 VULN: Embedded PEM RSA Private Key
RSA_PRIVATE_KEY = """-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA0Z3VS5JJcds3xHn/ygWep4PAtEsHABCDEFGHIJKLMNOPQRST
UVWXYZabcdefghijklmnopqrstuvwxyz01234567890ABCDEFGHIJKLMNOPQRSTU
(truncated for test pattern detection - real key would be 1700+ chars)
-----END RSA PRIVATE KEY-----"""

# ── CAT-09: JWT Signing Keys ──────────────────────────────────────────────────
# 🔴 VULN: Hardcoded JWT signing secret (CWE-321)
JWT_SECRET = "my_super_secret_jwt_signing_key_do_not_share"
JWT_REFRESH_SECRET = "refresh_token_secret_key_12345678"

# 🔴 VULN: Pre-signed JWT token with admin claims hardcoded
ADMIN_JWT_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiIsImlhdCI6MTUxNjIzOTAyMn0.fake_signature_for_demo"

# ── CAT-10: Generic API Keys ──────────────────────────────────────────────────
# 🔴 VULN: High-entropy API key patterns
OPENAI_API_KEY = "sk-proj-ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrst"
CLAUDE_API_KEY = "sk-ant-api03-ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdef"
DATADOG_API_KEY = "1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d"
PAGERDUTY_TOKEN = "u+aBcDeFgHiJkLmNoPqRsTuVwXyZ123456"
NEWRELIC_LICENSE = "eu01xxABCDEFGHIJKLMNOPQRSTUVWXYZ1234NRAL"

# ── APPLICATION USAGE (demonstrates how secrets get used wrongly) ─────────────
import os

def get_aws_client():
    """
    🔴 VULN: Reads from hardcoded constants above, not from os.environ!
    The correct approach: boto3.client('s3') with IAM role, no explicit keys.
    """
    import boto3
    # BAD: Using hardcoded constants — should use IAM roles or os.environ
    return boto3.client('s3',
        aws_access_key_id=AWS_ACCESS_KEY_ID,       # 🔴 BAD: Hardcoded!
        aws_secret_access_key=AWS_SECRET_ACCESS_KEY  # 🔴 BAD: Hardcoded!
    )

def connect_to_db():
    """🔴 VULN: Database credentials hardcoded in function body (CWE-259)"""
    # BAD: Both username and password committed to source control
    host = "prod-db.internal.megacorp.com"
    port = 5432
    database = "megacorp_prod"
    username = "admin"           # 🔴 BAD: Hardcoded!
    password = "SuperSecret123"  # 🔴 BAD: Hardcoded! Should be from Vault/SSM
    return f"postgresql://{username}:{password}@{host}:{port}/{database}"
