# 🚀 Getting Started with TigerGate CNAPP Test Suite

> **Welcome, fresher!** This guide walks you through every part of this project — no security background needed. By the end, you'll know exactly what every folder does and how to run the tests.

---

## 📖 What Is This Project?

**TigerGate** is a **CNAPP (Cloud-Native Application Protection Platform)** — a security product that scans your code, cloud configuration, containers, and runtime for vulnerabilities.

This repository is a **testing playground** for TigerGate. It contains **intentionally broken code and cloud configurations** so that security scanners have something to find and alert on.

> 💡 **Think of it like a crash-test car.** The car is *designed* to be broken in a crash — so engineers can test whether the safety systems work. This code is the crash-test car for security tools.

---

## ⚠️ Important Warning

> 🔴 **Never deploy this code to a real server or cloud account.**
> Every file here is intentionally insecure. It contains fake passwords, fake API keys, and vulnerable code written on purpose for testing.

---

## 🗺️ Project Map — What Every Folder Does

```
tigergate-test/
│
├── 📁 cspm/          → Cloud Security Posture (AWS, Azure, GCP, Oracle configs)
├── 📁 kspm/          → Kubernetes Security (container orchestration misconfigs)
├── 📁 cwpp/          → Container & Runtime Security (Docker, attack scripts)
├── 📁 cdr/           → Cloud Detection & Response (simulated attack detections)
├── 📁 ciem/          → Cloud Identity & Access (IAM permission misconfigs)
├── 📁 dspm/          → Data Security (PII/PHI data exposure)
├── 📁 ai_spm/        → AI Security (LLM prompt injection, unsafe model loading)
├── 📁 api/           → API Security (OWASP API Top 10 vulnerabilities)
│
├── 📁 sast_advanced/ → Code Vulnerabilities (SQL injection, RCE, deserialization)
├── 📁 sca/           → Software Composition Analysis (vulnerable libraries, SBOM)
├── 📁 secrets/       → Secrets Detection (hardcoded API keys, passwords)
├── 📁 iac/           → Infrastructure as Code (Terraform/CloudFormation/Ansible)
│
├── 📁 zero_trust/    → Zero Trust Architecture violations
├── 📁 supply_chain/  → Supply Chain Security (GitHub Actions attacks)
├── 📁 devsecops/     → DevSecOps (shift-left CI/CD pipeline examples)
├── 📁 attack_paths/  → Multi-hop attack path simulations
├── 📁 advanced_evasion/ → Evasion and obfuscation techniques
│
├── 📁 industry/      → Industry-specific modules
│   ├── fintech/      → FinTech (PCI-DSS payment card violations)
│   ├── healthcare/   → Healthcare (HIPAA patient data violations)
│   ├── government/   → Government (FedRAMP, CUI mishandling)
│   └── startup/      → Startup anti-patterns (move-fast security debt)
│
├── 📁 compliance/    → Compliance framework mappings (SOC2, PCI, HIPAA...)
├── 📁 nodejs/        → Node.js vulnerable web application
├── 📁 python/        → Python vulnerable web application
├── 📁 java/          → Java vulnerable web application
├── 📁 php/           → PHP vulnerable web application
├── 📁 ruby/          → Ruby vulnerable web application
├── 📁 runtime/       → Runtime attack simulations
│
├── 📁 mega-test-project/ → Docker Compose environment (runs all apps together)
├── 📁 .github/       → GitHub Actions CI/CD workflows
├── 📁 hooks/         → Git pre-commit hooks (secret scanning)
│
├── 📄 dashboard.html → Beautiful security coverage dashboard (open in browser!)
├── 📄 README.md      → Project overview
├── 📄 Makefile       → Run any scan with `make <command>`
└── 📄 GLOSSARY.md    → Security terms explained simply
```

---

## 🏁 Step-by-Step: How to Set Up

### Step 1 — Clone the Repository
```bash
git clone https://github.com/kuttiamk/tigergate-test.git
cd tigergate-test
```

### Step 2 — View the Dashboard (No Setup Required!)
```bash
# Just open this file in your browser
open dashboard.html
# OR on Linux:
xdg-open dashboard.html
```
This shows a visual map of all 18 security pillars covered.

### Step 3 — Install the Pre-commit Hook (optional)
```bash
make install-hooks
```
This runs a secret scanner every time you `git commit`.

### Step 4 — Run a Security Scan
```bash
# Run ALL security scanners at once:
make scan-all

# Or run individual scanners:
make scan-checkov     # Checks Terraform/CloudFormation IaC files
make scan-gitleaks    # Finds hardcoded secrets/passwords
make scan-trivy-sca   # Finds vulnerable libraries (Log4Shell, etc.)
make scan-hadolint    # Checks Dockerfiles for best practices
```

### Step 5 — Start the Full Multi-Language Environment
```bash
cd mega-test-project
docker compose up -d   # Starts Node.js, Python, Java, PHP apps together
```

---

## 🔍 How to Read the Vulnerable Files

Every vulnerable line is **clearly marked** so you know exactly what's wrong and why:

| Marker | Meaning |
|--------|---------|
| `🔴 VULN:` | This line has an intentional vulnerability |
| `# BAD:` or `// BAD:` | This is the wrong way to do it |
| `# GOOD:` | This shows the correct/safe approach |
| `# 🔴 CWE-89:` | Links to the official weakness database |
| `# FINDING:` | What a scanner should report here |

### Example — Reading a vulnerable Python file:

```python
# ❌ WRONG — This is vulnerable (don't do this):
query = f"SELECT * FROM users WHERE name = '{username}'"  # 🔴 SQL Injection!
cursor.execute(query)

# ✅ CORRECT — This is the safe way:
cursor.execute("SELECT * FROM users WHERE name = ?", (username,))
```

---

## 🎯 Key Concepts — Plain English

### What is SQL Injection?
> An attacker types SQL code into a form field (like a search box) and your database runs it. Example: typing `'; DROP TABLE users; --` into a search field could delete your database.

### What is Hardcoded Credentials?
> Putting passwords directly in your code file instead of using environment variables or a secrets manager. Bad because anyone who reads your code (or steals your git history) gets your passwords.

### What is a Misconfigured S3 Bucket?
> An Amazon S3 storage bucket set to "public" accidentally. This is like leaving your filing cabinet unlocked on the street. Anyone can read or download your files.

### What is Privilege Escalation?
> Gaining more access than you're supposed to have. Example: a normal user becomes an admin by exploiting a bug.

### What is SAST vs SCA?
> - **SAST** (Static Application Security Testing) = scanning your *own* code for bugs
> - **SCA** (Software Composition Analysis) = scanning your *imported libraries* for known CVEs

---

## 📚 Learning Path for Freshers

If you're new to security, follow this order:

1. **Start here** → Open `dashboard.html` to see the full picture
2. **Read** → `GLOSSARY.md` for all security terms explained simply
3. **Explore Code** → `nodejs/server.js` — the most readable vulnerable app
4. **Explore IaC** → `cspm/aws_insecure.tf` — Terraform with CIS violations (well commented)
5. **Explore Secrets** → `secrets/secrets_all_formats.py` — see what secrets look like
6. **Explore CI/CD** → `.github/workflows/insecure-ci.yml` — broken pipeline
7. **Explore Industry** → `industry/fintech/payment_processing.py` — real-world PCI violations
8. **Run a scan** → `make scan-gitleaks` — see secrets get detected
9. **Read compliance** → `compliance/COMPLIANCE_MAPPING.md` — how code maps to regulations

---

## 🛠️ Common Commands Reference

```bash
make help           # Show all available commands
make scan-all       # Run every security scanner
make scan-gitleaks  # Detect hardcoded secrets
make scan-checkov   # Scan Terraform/CloudFormation
make scan-semgrep   # SAST scan (code vulnerabilities)
make scan-trivy-sca # Vulnerable library scan
make scan-hadolint  # Dockerfile linting
make count-vulns    # Count total vulnerability markers
make open-dashboard # Open security coverage dashboard
make install-hooks  # Install pre-commit security hook
```

---

## ❓ FAQ

**Q: Are these real security vulnerabilities?**
A: Yes! Every vulnerability in this repo is real and exploitable on a live system. They are here so scanners can detect them.

**Q: Why do the files have real-looking AWS keys?**
A: These are fake test keys in the format that AWS keys use (starting with `AKIA...`). They don't grant access to anything. They're here to test secret detection tools.

**Q: What is a CNAPP?**
A: Cloud-Native Application Protection Platform. A security product that covers your entire software lifecycle — from code (SAST) to cloud (CSPM) to runtime (CWPP).

**Q: Can I contribute a new vulnerability?**
A: Yes! See `CONTRIBUTING.md` for guidelines on adding new test cases.

---

## 📞 Links

| Resource | Link |
|----------|------|
| Dashboard | [dashboard.html](./dashboard.html) |
| Glossary | [GLOSSARY.md](./GLOSSARY.md) |
| Compliance Map | [compliance/COMPLIANCE_MAPPING.md](./compliance/COMPLIANCE_MAPPING.md) |
| Contributing | [CONTRIBUTING.md](./CONTRIBUTING.md) |
| Security Policy | [SECURITY.md](./SECURITY.md) |
| OWASP Top 10 | https://owasp.org/Top10/ |
| CWE Database | https://cwe.mitre.org |
| CVE Database | https://cve.mitre.org |
| MITRE ATT&CK Cloud | https://attack.mitre.org/matrices/enterprise/cloud/ |
