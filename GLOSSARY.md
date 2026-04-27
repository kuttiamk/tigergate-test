# 📖 Security Glossary — Plain English Definitions

> Every security term used in this project, explained simply. No prior knowledge needed.

---

## A

**Access Control**
> Rules about who can see or use what. Like requiring your badge to open a door at work. In software, it's making sure logged-in users can only access their own data.

**API (Application Programming Interface)**
> A way for two programs to talk to each other. Like a waiter who takes your order (request) to the kitchen (server) and brings back your food (response).

**API Key**
> A secret password used by programs to prove their identity when calling an API. Like a membership card — if someone steals it, they can impersonate you.

**Attack Path**
> The chain of steps an attacker takes to reach their goal. Like a path through a maze. Example: find open port → exploit vulnerability → access database → steal data.

---

## B

**BOLA (Broken Object Level Authorization)**
> Also called IDOR. When a user can access another user's data just by changing a number in the URL. Example: changing `/api/users/123` to `/api/users/124` to see someone else's profile.

**Brute Force Attack**
> Trying every possible password until one works. Like trying every combination on a padlock.

---

## C

**CIEM (Cloud Identity and Entitlement Management)**
> Managing who (users, apps, services) has permission to do what in your cloud environment. Misconfigured permissions are one of the most common cloud security issues.

**CNAPP (Cloud-Native Application Protection Platform)**
> An all-in-one security platform covering code → cloud → runtime. TigerGate is a CNAPP.

**CSPM (Cloud Security Posture Management)**
> Continuously scanning your cloud configuration (e.g., AWS settings) to find things set up insecurely, like a publicly readable S3 bucket.

**CUI (Controlled Unclassified Information)**
> US government term for sensitive-but-not-classified information that must still be protected. Similar concept to PII but for government data.

**CVE (Common Vulnerabilities and Exposures)**
> A public database of known security bugs in software. Each gets a unique ID like `CVE-2021-44228` (Log4Shell). If your software is on this list, attackers know exactly how to exploit it.

**CVSS Score**
> A number from 0 to 10 rating how severe a vulnerability is. 10 = run and patch immediately. Example: Log4Shell = CVSS 10.0 (Critical).

**CWPP (Cloud Workload Protection Platform)**
> Security for running containers and virtual machines — detecting attacks happening live in your cloud workloads.

---

## D

**Dependency Confusion**
> An attack where a malicious package with the same name as your internal package gets installed from the public internet instead. Your build system gets tricked into installing malware.

**Deserialization**
> Converting stored data back into a live object. Dangerous when attacker-controlled data is deserialized — it can execute code. `CVE-2017-5941` is a famous Node.js deserialization RCE.

**DSPM (Data Security Posture Management)**
> Tracking where sensitive data (SSNs, credit cards, health records) lives in your cloud and whether it's protected.

---

## E

**EDR (Endpoint Detection & Response)**
> Security software running on a computer that watches for malicious activity and can stop it. Like a security guard for each machine.

**Environment Variable**
> A setting stored in the operating system (not in code). The safe way to pass secrets to applications. Example: `export DB_PASSWORD=secret123` instead of writing it in your Python file.

---

## F

**FedRAMP**
> US government security certification required for cloud services used by federal agencies. Based on NIST SP 800-53 controls.

**FIPS 140-2**
> US government standard for cryptographic modules. If you handle sensitive government data, your encryption must use FIPS-validated algorithms.

---

## G

**GuardDuty**
> AWS's built-in threat detection service. Watches your AWS account for suspicious activity like unusual API calls or connections from known malicious IPs.

---

## H

**HIPAA**
> US law protecting medical patient data (PHI). Healthcare apps must encrypt data, log access, and restrict who can see patient records.

**Hardcoded Credentials**
> Passwords or API keys typed directly into source code. Like leaving your house key glued to the front door.

---

## I

**IAM (Identity and Access Management)**
> The system for managing who can do what in a cloud environment. AWS IAM, Azure RBAC, and GCP IAM are examples. A misconfigured IAM role can give an attacker admin access.

**IDOR (Insecure Direct Object Reference)**
> See BOLA. Accessing another user's resource by guessing or incrementing an ID.

**IaC (Infrastructure as Code)**
> Defining cloud resources (servers, databases, networks) in code files (Terraform, CloudFormation, Ansible) instead of clicking through a UI. Enables automated scanning for misconfigs.

---

## J

**JWT (JSON Web Token)**
> A compact token used for authentication. Contains user claims and is signed with a secret key. If the secret key is weak or the algorithm is set to "none", attackers can forge tokens.

---

## K

**KSPM (Kubernetes Security Posture Management)**
> Scanning Kubernetes cluster configurations for security issues, like containers running as root or missing network policies.

---

## L

**Lateral Movement**
> After gaining initial access, an attacker moves through the network to reach more valuable targets. NetworkPolicies in Kubernetes help prevent this.

**Least Privilege**
> Give every user/service only the minimum permissions they need — nothing more. A database service shouldn't have permission to delete S3 buckets.

**Log4Shell (CVE-2021-44228)**
> One of the worst vulnerabilities in history. A bug in the Log4j Java logging library (CVSS 10.0) that lets attackers run any code on any server just by sending a specially crafted log message.

**LoTL (Living off the Land)**
> Attackers using legitimate built-in tools (like curl, bash, ssh, PowerShell) instead of malware — making them harder to detect since the tools are expected to be there.

---

## M

**MITRE ATT&CK**
> A public knowledge base of attacker tactics and techniques. Used to classify attacks. Example: T1530 = "Data from Cloud Storage Object" (S3 data theft).

**MFA (Multi-Factor Authentication)**
> Requiring a second proof of identity beyond just a password (e.g., an OTP sent to your phone). Prevents account takeover even if password is stolen.

**Micro-segmentation**
> Splitting a network into very small zones, each with its own access rules. Prevents one compromised service from reaching everything else.

---

## N

**NetworkPolicy**
> A Kubernetes rule that controls which pods can communicate with which other pods. Without it, all pods can talk to each other (implicit trust = security risk).

**NIST**
> US National Institute of Standards and Technology. Publishes security standards (NIST 800-53, 800-207 for Zero Trust) used by governments and enterprises worldwide.

---

## O

**OWASP**
> Open Worldwide Application Security Project. Publishes free security guides including the famous OWASP Top 10 (most common web vulnerabilities) and OWASP API Top 10.

**OWASP Top 10**
>  The 10 most critical web application security risks: Injection, Broken Auth, XSS, Insecure Design, etc.

---

## P

**PAN (Primary Account Number)**
> The 16-digit credit card number. PCI-DSS requires it to be masked (show only last 4 digits) and never stored unless encrypted.

**PCI-DSS**
> Payment Card Industry Data Security Standard. Rules for any company that processes credit cards. Violations can result in fines and loss of payment processing ability.

**PHI (Protected Health Information)**
> Patient health data protected by HIPAA. Includes names, dates, diagnoses, SSNs, medical record numbers.

**PII (Personally Identifiable Information)**
> Any data that can identify a specific person: name, email, SSN, phone number, IP address, etc.

**Privilege Escalation**
> Gaining more access rights than you should have. On AWS, this often involves chaining IAM role assumptions to reach admin-level access.

**Prototype Pollution**
> A JavaScript vulnerability where an attacker injects properties into the base `Object.prototype`, affecting all objects in the application.

---

## R

**RCE (Remote Code Execution)**
> The most dangerous vulnerability type — an attacker can run their own code on your server. Can lead to full system takeover.

**RBAC (Role-Based Access Control)**
> Assigning permissions based on a user's role (admin, editor, viewer) rather than to each individual user.

---

## S

**SAST (Static Application Security Testing)**
> Scanning source code for vulnerabilities without running it. Tools: SonarQube, Semgrep, Checkmarx.

**SCA (Software Composition Analysis)**
> Scanning your imported open-source libraries for known CVEs. Tools: Trivy, Snyk, Grype.

**SBOM (Software Bill of Materials)**
> A complete list of all software components (libraries, versions) in your application — like a food ingredient label for software.

**Secrets Management**
> Storing passwords, API keys, and certificates in a dedicated secure system (AWS Secrets Manager, HashiCorp Vault) instead of hardcoding them in files.

**Shell Injection / OS Command Injection (CWE-78)**
> When user input is passed to a system shell command without sanitization. Example: `os.system("ping " + user_input)` — attacker enters `; rm -rf /`.

**SSRF (Server-Side Request Forgery)**
> An attacker tricks your server into making HTTP requests to internal addresses (like `http://169.254.169.254` — AWS metadata service) to steal credentials.

**SQL Injection (CWE-89)**
> Inserting SQL code into user input fields to manipulate database queries. Example: entering `' OR '1'='1` into a login form to bypass authentication.

**SSTI (Server-Side Template Injection)**
> Injecting code into a template engine (Jinja2, Twig, Freemarker). Can escalate to RCE. Example in Jinja2: `{{7*7}}` renders as `49` — if user controls this, they control your server.

**Supply Chain Attack**
> Compromising software at the source — infecting a library, build tool, or CI/CD pipeline that others depend on. Famous examples: SolarWinds, XZ Utils, Codecov.

---

## T

**TLS (Transport Layer Security)**
> The encryption protocol that makes HTTPS work. Data sent over plain HTTP can be read by anyone on the network. TLS encrypts it.

**Terraform**
> An Infrastructure as Code tool. Defines AWS/Azure/GCP resources in `.tf` files. Can be scanned by Checkov and tfsec for misconfigurations.

**TruffleHog / Gitleaks / GitGuardian**
> Tools that scan git repositories for accidentally committed secrets (passwords, API keys).

---

## V

**Vulnerability**
> A weakness in software that can be exploited by an attacker. Not all vulnerabilities are equally dangerous — CVSS scores help prioritize.

---

## X

**XSS (Cross-Site Scripting)**
> Injecting malicious JavaScript into a web page that other users see. Can steal cookies, redirect users, or deface websites.

**XXE (XML External Entity)**
> A vulnerability in XML parsers where an attacker can read files from the server or make internal network requests by including special XML entities.

---

## Z

**Zero Trust**
> A security model that assumes no user, device, or service is trusted by default — even if they're inside your network. Every access request must be verified. Based on NIST SP 800-207.

---

*This glossary covers terms used in this project. For more depth, visit [OWASP](https://owasp.org), [CWE](https://cwe.mitre.org), or [MITRE ATT&CK](https://attack.mitre.org).*
