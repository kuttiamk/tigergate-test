# TigerGate CNAPP Platform Simulator

Welcome to the **TigerGate CNAPP Test Suite**! 🚀
This repository contains a comprehensive, highly-structured collection of modern applications, scripts, and Infrastructure-as-Code (IaC) templates purposely built with severe security vulnerabilities.

Its sole purpose is to act as the ultimate training and testing ground for evaluating **TigerGate's** holistic Cloud Native Application Protection Platform (CNAPP) capabilities.

## What's Inside?
This repository is categorized strictly by the security domains that TigerGate intercepts:
- `cspm/`: Cloud Security Posture configurations (AWS, Azure, GCP, Oracle) missing encryption or open to the internet.
- `ciem/`: Identity & Access Management (IAM/RBAC) templates assigning excessively broad privileges.
- `cwpp/`: Container workloads containing old CVEs and compromised host settings.
- `kspm/`: Kubernetes YAML templates running privileged, root-access pods.
- `ai_spm/`: Exposed HuggingFace SageMakers and LLM prompt injections.
- `api/`: REST, GraphQL, and SOAP API components suffering from Auth, DoS, and XXE flaws.
- `dspm/`: Dedicated simulated databases tagged for PII/HIPAA stripped of encryption.
- `serverless/`: Lambda functions containing code-level injection vectors.
- `python/`, `ruby/`, `nodejs/`, `java/`: Broad SaaS Application templates with SQLi, SSRF, XSS, etc.

## Quick Start
Check out the `Makefile` or just run:
```bash
make help
```
