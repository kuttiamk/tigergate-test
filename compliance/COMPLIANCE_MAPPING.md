# TigerGate CNAPP – Complete Code-to-Cloud Coverage
# Compliance Framework Mapping

## SOC 2 Type II — Trust Service Criteria

| Criteria | Control | TigerGate File | Finding |
|----------|---------|----------------|---------|
| CC6.1 | Logical & Physical Access Controls | `ciem/overly_permissive_iam.tf` | Action:* Resource:* violates least-privilege |
| CC6.2 | User Registration & De-provisioning | `ciem/cross_account.tf` | Principal:* — any entity can assume role |
| CC6.3 | Role-Based Access Control | `kspm/vulnerable_deployment.yaml` | default SA bound to cluster-admin |
| CC6.6 | Intrusion Detection | `cwpp/runtime/runtime_attack_advanced.sh` | No EDR/IDS for rogue processes |
| CC6.7 | Transmission Encryption | `sast_advanced/ssti_jinja.py` | HTTP API without HTTPS |
| CC7.1 | Change Management | `.github/workflows/insecure-ci.yml` | No approval gate before production deploy |
| CC7.2 | Anomaly Detection | `cdr/cloudtrail_events.json` | CloudTrail disabled — gaps in audit |
| CC8.1 | Change Authorization | `.github/CODEOWNERS` | Non-existent team auto-approves PRs |
| CC9.1 | Risk Mitigation | `attack_paths/lateral_movement.tf` | 5-hop unmitigated attack path |

---

## PCI-DSS v4.0 — Payment Card Industry

| Requirement | Control Area | TigerGate File | Finding |
|-------------|-------------|----------------|---------|
| Req 2.2 | Secure Configuration | `cspm/aws_insecure.tf` | Public buckets, no encryption |
| Req 3.4 | PAN Masking | `industry/fintech/payment_processing.py` | Full PAN stored in plaintext |
| Req 3.5 | CVV Not Stored | `industry/fintech/payment_processing.py` | CVV stored in DB post-auth |
| Req 4.2 | Transmission Encryption | `industry/fintech/payment_processing.py` | Payment endpoint on HTTP |
| Req 6.3 | Vulnerability Management | `sca/sbom_cyclonedx.json` | Log4Shell (CVSS 10.0) in SBOM |
| Req 6.4 | Secure Coding | `nodejs/server.js` | eval() RCE, SQLi on user input |
| Req 8.3 | MFA for Admin | `industry/fintech/payment_processing.py` | Admin endpoint — no auth at all |
| Req 10.2 | Audit Logging | `industry/fintech/payment_processing.py` | Transactions not audit-logged |
| Req 12.3 | Tokenization | `dspm/pii_phi_data.sql` | Raw card numbers in database |

---

## ISO 27001:2022 — Information Security Management

| Control | Domain | TigerGate File | Finding |
|---------|--------|----------------|---------|
| A.5.15 | Access Control | `ciem/overly_permissive_iam.tf` | Over-privileged IAM |
| A.5.23 | Cloud Services | `cspm/aws_insecure.tf` | No shared responsibility boundaries |
| A.7.9 | Clear Desk/Screen | `secrets/secrets_all_formats.py` | Credentials in source code |
| A.8.5 | Secure Authentication | `zero_trust/network_segmentation.tf` | Static long-lived credentials |
| A.8.9 | Configuration Mgmt | `iac/cloudformation_insecure.yaml` | Insecure defaults deployed |
| A.8.16 | Monitoring | `cdr/cloudtrail_events.json` | CDR shows gaps in monitoring |
| A.8.20 | Network Security | `zero_trust/network_segmentation.tf` | No micro-segmentation |
| A.8.24 | Cryptography | `docker/Dockerfile.insecure` | Secrets baked into image layer |
| A.8.25 | Secure Development | `.github/workflows/insecure-ci.yml` | No SAST gate in pipeline |

---

## FedRAMP Moderate Baseline — NIST 800-53 Rev 5

| Control | Family | TigerGate File | Finding |
|---------|--------|----------------|---------|
| AC-2 | Account Management | `industry/government/fedramp_violations.tf` | No IAM users (root used) |
| AC-17 | Remote Access | `industry/government/fedramp_violations.tf` | No MFA for remote access |
| AU-2 | Audit Events | `industry/government/fedramp_violations.tf` | CloudTrail not multi-region |
| CM-7 | Least Functionality | `industry/government/fedramp_violations.tf` | SSH/RDP open to 0.0.0.0/0 |
| IA-5 | Authenticator Management | `industry/government/fedramp_violations.tf` | Weak password policy |
| SA-22 | Unsupported System Components | `industry/government/fedramp_violations.tf` | Windows Server 2012 R2 (EOL) |
| SC-8 | Transmission Confidentiality | `industry/government/fedramp_violations.tf` | TLS 1.0 policy on ALB |
| SC-28 | Protection at Rest | `industry/government/fedramp_violations.tf` | No FIPS 140-2 encryption |
| SI-2 | Flaw Remediation | `sca/sbom_cyclonedx.json` | Critical CVEs not patched |

---

## HIPAA Security Rule — Healthcare

| Safeguard | Section | TigerGate File | Finding |
|-----------|---------|----------------|---------|
| Access Control | §164.312(a)(1) | `industry/healthcare/ehr_system.py` | PHI accessible anonymously |
| Audit Controls | §164.312(b) | `industry/healthcare/ehr_system.py` | PHI access not logged |
| Integrity | §164.312(c) | `dspm/pii_phi_data.sql` | No integrity checks on PHI |
| Encryption (Transit) | §164.312(e)(1) | `industry/healthcare/ehr_system.py` | PHI over HTTP |
| Encryption (Rest) | §164.312(a)(2)(iv) | `cspm/aws_insecure.tf` | S3 with PHI, no server-side encryption |
| Workforce Training | §164.308(a)(5) | `code_quality/complex_spaghetti.py` | Dangerous patterns (silent exceptions) |
| PHI Minimum Necessary | §164.502(b) | `industry/healthcare/ehr_system.py` | Returns all PHI in every response |
