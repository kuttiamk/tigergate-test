# 📁 `iac/` — Infrastructure as Code Security

## What Is This?

**IaC (Infrastructure as Code)** means defining your cloud servers, databases, networks,
and more in code files instead of clicking through a web console. The big benefit: you can
put these files in git and review them — and security teams can **scan them automatically**
before anything is deployed.

This folder contains intentionally misconfigured IaC files to test CNAPP IaC scanners.

## What's In This Folder?

| File | Tool | What It Tests |
|------|------|--------------|
| `main.tf` | Terraform | Core AWS infrastructure misconfigs |
| `cloudformation_insecure.yaml` | CloudFormation | 10 AWS CFN findings (cfn-nag) |
| `ansible_insecure.yaml` | Ansible | 6 server configuration violations |

## IaC vs. Clicking Through a Console

```
❌ Without IaC (clicking):
  - Changes aren't tracked → can't review what changed
  - No automated security scanning before deployment
  - Hard to repeat or audit

✅ With IaC (Terraform/CloudFormation):
  - Everything is in git → full history, code review, PR approval
  - Checkov/tfsec can scan before deployment (shift-left!)
  - Any misconfiguration is caught before it reaches production
```

## Top Violations in This Folder

### Terraform (`main.tf`, `cloudformation_insecure.yaml`)
| Finding | Why It's Dangerous |
|---------|-------------------|
| `publicly_accessible = true` on RDS | Database exposed to entire internet |
| `storage_encrypted = false` | Data at rest readable if disk is stolen |
| `acl = "public-read"` on S3 | Anyone can download your files |
| Security group port 22 from `0.0.0.0/0` | SSH open to everyone — brute-forceable |
| CloudTrail `is_multi_region_trail = false` | Attackers in other regions go unlogged |
| Hardcoded credentials in `user_data` | EC2 startup script contains passwords |

### Ansible (`ansible_insecure.yaml`)
| Finding | Why It's Dangerous |
|---------|-------------------|
| `StrictHostKeyChecking no` | Man-in-the-middle attacks possible |
| Secrets in `vars:` not Ansible Vault | Anyone who reads the playbook gets passwords |
| `shell:` module with variables | Command injection if variable contains `;` |
| `validate_certs: no` | Downloads packages without TLS verification |
| `mode: '0644'` on secret file | World-readable config with passwords |

## How to Scan These Files

```bash
# Scan all Terraform files
make scan-checkov
# OR
checkov -d . --framework terraform

# Scan CloudFormation
checkov -f iac/cloudformation_insecure.yaml --framework cloudformation

# Lint Ansible playbooks
ansible-lint iac/ansible_insecure.yaml
```

## Learn More
- [GLOSSARY.md](../GLOSSARY.md) → look up: IaC, Terraform, Least Privilege
- [Checkov Documentation](https://www.checkov.io/1.Welcome/What%20is%20Checkov.html)
- [CIS AWS Benchmarks](https://www.cisecurity.org/benchmark/amazon_web_services)
