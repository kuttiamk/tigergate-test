# 📁 `devsecops/` — DevSecOps & Shift-Left Security

## What Is This?

**DevSecOps** = Development + Security + Operations.

The idea is to move security checks as early as possible in the development process —
this is called **"shifting left"** (because time flows left to right on a timeline,
and you're moving security earlier).

```
Traditional:  [Code] → [Build] → [Test] → [Deploy] → [SECURITY CHECK] ← too late!
Shift-Left:   [SECURITY CHECK] → [Code] → [Build] → [Test] → [Deploy] ← much better!
```

## What's In This Folder?

| File | Purpose |
|------|---------|
| `shift_left_pipeline.yml` | Complete 7-stage secure CI/CD pipeline (the GOLD STANDARD) |
| `semgrep_rules.yaml` | Custom Semgrep SAST rules tuned for this repo |

## The 7 Pipeline Stages Explained

```
Stage 1: Secrets Detection (Gitleaks)
  → Fails immediately if any passwords/keys are committed
  → Prevents secrets from ever reaching the codebase

Stage 2: SAST — Static Code Analysis (Semgrep)
  → Scans Python, JavaScript, Java code for vulnerabilities
  → Finds SQL injection, XSS, eval() usage, etc.
  → Reports in SARIF format (viewable in GitHub Security tab)

Stage 3: SCA & SBOM (Trivy)
  → Finds vulnerable libraries (e.g., Log4Shell in log4j 2.14.1)
  → Generates a Software Bill of Materials (SBOM) — an ingredient list

Stage 4: IaC Security (Checkov)
  → Scans Terraform/CloudFormation for misconfigs before they're deployed
  → Checks against CIS Benchmarks and 1000+ rules

Stage 5: Container Security (Trivy + Hadolint)
  → Scans Dockerfiles for bad practices
  → Scans built container images for OS-level CVEs

Stage 6: DAST — Dynamic Analysis (OWASP ZAP)
  → Spins up the actual app and attacks it like a real pen tester
  → Finds runtime issues that static scanning can't

Stage 7: Compliance Report
  → Generates a markdown report showing pass/fail for each framework
```

## Custom Semgrep Rules (`semgrep_rules.yaml`)

This file adds TigerGate-specific detection rules that standard rulesets miss:
- `eval(request.args.get(...))` → flags Python RCE via eval
- `cursor.execute(f"...{variable}...")` → flags f-string SQL injection
- `jwt.decode(options={"verify_signature": False})` → flags JWT alg confusion
- `publicly_accessible = true` in Terraform → flags public RDS

## Comparing the Two Pipelines

| | `insecure-ci.yml` | `shift_left_pipeline.yml` |
|--|---------------------|--------------------------|
| Secret scanning | ❌ No | ✅ Yes (Gitleaks) |
| SAST | ❌ Fake/unverified | ✅ Semgrep (real) |
| Permissions | ❌ Over-permissioned | ✅ Read-only |
| Pinned actions | ❌ No (`@latest`) | ✅ Yes (SHA pinned) |
| Fork PR safety | ❌ No | ✅ Separated |
| Compliance report | ❌ No | ✅ Yes |

## Run the Custom Semgrep Rules

```bash
semgrep --config devsecops/semgrep_rules.yaml .
```

## Learn More
- [GLOSSARY.md](../GLOSSARY.md) → look up: SAST, SCA, SBOM, DAST
- [OWASP CI/CD Security Risks](https://owasp.org/www-project-top-10-ci-cd-security-risks/)
