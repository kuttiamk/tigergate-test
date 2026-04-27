# 📁 `industry/` — Industry-Specific Security Violations

## What Is This?

Different industries have different **compliance regulations** — legal rules about how they must protect data. If a company breaks these rules, they can face fines, lawsuits, and loss of operating licenses.

This folder contains code and IaC that intentionally violates each industry's regulations — so TigerGate can demonstrate detection of industry-specific risks.

---

## 📁 `fintech/` — Financial Technology (PCI-DSS)

**Regulation:** PCI-DSS v4.0 (Payment Card Industry Data Security Standard)
**Who must comply:** Any company that processes, stores, or transmits credit card data.
**Penalty for failure:** Fines up to $100,000/month, loss of ability to accept card payments.

| File | What It Demonstrates |
|------|---------------------|
| `payment_processing.py` | Storing full card numbers + CVV in plaintext, HTTP (not HTTPS) payment endpoint |
| `trading_api.js` | Rate limiting bypass, order manipulation |
| `fintech_iac.tf` | Unencrypted payment database, public RDS, no access logging |

**Key rule violated:** PCI-DSS Req 3.4 — "Render PAN unreadable anywhere it is stored."

---

## 📁 `healthcare/` — Healthcare (HIPAA)

**Regulation:** HIPAA Security Rule (US Health Insurance Portability and Accountability Act)
**Who must comply:** Hospitals, clinics, health apps, health insurance companies.
**Penalty for failure:** Fines up to $1.9M per violation category per year.

| File | What It Demonstrates |
|------|---------------------|
| `ehr_system.py` | Patient PHI accessible without login, no audit log, SQL injection on PHI |
| `healthcare_iac.tf` | PHI S3 bucket publicly readable, EHR database exposed to internet |

**Key rule violated:** HIPAA §164.312(b) — "Implement hardware, software, and procedural mechanisms that record and examine activity in information systems that contain PHI."

---

## 📁 `government/` — Government (FedRAMP / CMMC)

**Regulation:** FedRAMP Moderate (NIST SP 800-53) + CMMC (Cybersecurity Maturity Model Certification)
**Who must comply:** Any company providing cloud services to US federal agencies.
**Penalty for failure:** Loss of federal contracts, debarment from government business.

| File | What It Demonstrates |
|------|---------------------|
| `fedramp_violations.tf` | No MFA, TLS 1.0, EOL OS (Win Server 2012), no FIPS encryption |
| `sensitive_data_handler.py` | CUI transmitted without encryption, stored in plaintext, no audit log |

**Key rule violated:** FedRAMP AC-17 — "Implement managed access control points for remote access."

---

## 📁 `startup/` — Startups (Anti-Patterns)

**Problem:** Startups often prioritize speed over security ("we'll fix it later"). By the time they fix it, the technical debt is enormous and attackers have found it first.

| File | What It Demonstrates |
|------|---------------------|
| `rapid_deploy.tf` | Root creds in code, all ports open, no backups, debug mode in production |
| `misconfigured_saas.js` | Multi-tenancy data leak, IDOR, no rate limiting, verbose error messages |

**Common startup mistakes:**
- Using root AWS credentials instead of IAM roles
- "allow-everything" security groups
- No database backups (1 mistake = total data loss)

---

## How to Use These Files for Testing

```bash
# Scan all industry Terraform for IaC violations
make scan-checkov

# Test secret detection in startup code
make scan-gitleaks

# Run SAST on Python healthcare code
semgrep --config auto industry/healthcare/
```

## Compliance Mapping
See [`../compliance/COMPLIANCE_MAPPING.md`](../compliance/COMPLIANCE_MAPPING.md) for a full table mapping each control to the specific file that violates it.
