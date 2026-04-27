# 📁 `secrets/` — Secrets Detection Test Fixtures

## What Is This?

"Secrets" in security means **passwords, API keys, tokens, and certificates** that got accidentally committed into source code. Once a secret is in git history, even if deleted, it may be permanently exposed.

This folder contains **fake secrets in many different formats** — designed to test whether your secret scanning tools (Gitleaks, TruffleHog, GitGuardian) can detect each format.

> ⚠️ **These are all fake/test values.** They look real but grant access to nothing.

## What's In This Folder?

| File | Purpose |
|------|---------|
| `secrets_all_formats.py` | 20+ secret patterns (AWS, GCP, Azure, GitHub, Stripe, JWT) |
| `hardcoded_credentials.txt` | Raw credentials in a text file |
| `gitleaks.toml` | Custom Gitleaks rules tuned for this repository |

## Why Are Secrets Dangerous?

```python
# ❌ BAD — Password in source code (visible to everyone with git access)
DB_PASSWORD = "megacorp_prod_pass_123"   # 🔴 Anyone who clones this repo knows your DB password!

# ✅ GOOD — Password from environment variable
import os
DB_PASSWORD = os.environ.get("DB_PASSWORD")  # Loaded at runtime, not stored in code
```

If you commit a real AWS key, within minutes automated bots scan GitHub and can:
1. Spin up thousands of crypto-mining VMs on your account
2. Delete your data
3. Rack up a $50,000+ AWS bill

## How to Scan for Secrets

```bash
# Scan the whole repository
make scan-gitleaks

# Or run directly:
gitleaks detect --config secrets/gitleaks.toml --source . --verbose
```

## The Custom Rules (`gitleaks.toml`)

The file `gitleaks.toml` adds 8 extra detection patterns on top of Gitleaks' built-in rules:
- AWS `AKIA...` format
- GCP `AIza...` keys
- Stripe `sk_live_...` keys
- Slack `xoxb-...` tokens
- GitHub `ghp_...` PATs
- JWT signing secrets
- Database password patterns
- OpenAI / Anthropic API keys

## Learn More
- [GLOSSARY.md](../GLOSSARY.md) → look up: Hardcoded Credentials, API Key, Secrets Management
- [OWASP A07:2021 – Identification and Authentication Failures](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/)
