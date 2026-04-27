# 📁 `cdr/` — Cloud Detection & Response

## What Is This?

CDR (Cloud Detection & Response) is the security discipline of **detecting attacks happening in real-time in your cloud** and responding to them quickly.

Think of it like security cameras + a response team for your AWS account. When something suspicious happens (a user downloads 10,000 files at 3am from a new country), CDR tools alert you and can automatically block the activity.

**AWS GuardDuty** is Amazon's built-in CDR service. TigerGate integrates with GuardDuty findings.

## What's In This Folder?

| File | What It Simulates |
|------|------------------|
| `suspicious_api_calls.sh` | Runs simulated AWS API calls that trigger GuardDuty findings |
| `cloudtrail_events.json` | Sample GuardDuty finding events in JSON format |

## The 6 CDR Scenarios Simulated

| Scenario | MITRE Technique | Severity | What Happened |
|----------|----------------|----------|---------------|
| CDR-001 | T1078.004 | HIGH | Login from TOR exit node at 3:47 AM |
| CDR-002 | T1069.003 | MEDIUM | 47 IAM API calls in 90 seconds (enumeration) |
| CDR-003 | T1530 | CRITICAL | 4.7 GB of PII data copied to attacker S3 bucket |
| CDR-004 | T1562.008 | CRITICAL | CloudTrail logging disabled (going dark) |
| CDR-005 | T1078.004 | CRITICAL | 3-hop role chain → full account takeover |
| CDR-006 | T1496 | HIGH | Lambda function mining cryptocurrency |

## How Does an Attack Chain Work?

```
1. INITIAL ACCESS: Attacker gets stolen credentials (phishing, breach, dark web)
2. DISCOVERY: Runs ListUsers, ListRoles 47 times to map your IAM setup
3. COLLECTION: Downloads 4.7GB of PII from S3
4. EVASION: Disables CloudTrail so further activity is unlogged
5. PRIVILEGE ESCALATION: Chains 3 role assumptions to get Admin access
6. IMPACT: Creates backdoor admin user, starts crypto miner
```

## Running the Simulation

```bash
# Run the CDR scenario simulator (safe — no real AWS calls)
bash cdr/suspicious_api_calls.sh
```

## Key Concept: CloudTrail

AWS CloudTrail is like an activity log for your entire AWS account. Every API call is recorded:
- Who called it (user/role)
- When (timestamp)
- From where (IP address)
- What parameters were used

If an attacker disables CloudTrail (CDR-004), they can operate undetected. This is why
HIPAA, FedRAMP, and SOC 2 all *require* CloudTrail to always be on.

## Learn More
- [GLOSSARY.md](../GLOSSARY.md) → look up: GuardDuty, MITRE ATT&CK
- [MITRE ATT&CK Cloud Matrix](https://attack.mitre.org/matrices/enterprise/cloud/)
