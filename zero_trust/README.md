# 📁 `zero_trust/` — Zero Trust Architecture

## What Is This?

**Zero Trust** is a security model with one core principle:

> **"Never trust, always verify."**

Traditional security said: "If you're inside our network, we trust you."
Zero Trust says: "We *never* trust anyone — not even your own employees — without verification."

This folder demonstrates what a **broken** Zero Trust implementation looks like — so TigerGate can detect it.

## Zero Trust vs Traditional Security

```
Traditional Network Security:
  Internet → [Firewall] → TRUSTED ZONE (everyone inside can do anything)
  ↑ If attacker gets past firewall, they own everything

Zero Trust:
  Internet → [Firewall] → [Identity Verify] → [Device Check] → [Minimal Access]
  ↑ Even inside the "network", every request is verified every time
```

## What's In This Folder?

| File | What It Violates |
|------|----------------|
| `network_segmentation.tf` | ZT-001 to ZT-005: Flat network, no micro-segmentation, static credentials |
| `identity_verification.py` | ZT-ID-001 to ZT-ID-005: JWT alg:none, weak TOTP, no device posture |

## The 5 Zero Trust Architecture Violations (Network)

| Violation | Simple Explanation |
|-----------|-------------------|
| **ZT-001** | VPC membership = trusted. All pods in the same VPC talk freely. One compromised pod → all pods. |
| **ZT-002** | One giant /8 subnet = 16 million IPs in one trust zone. Should be many small subnets. |
| **ZT-003** | Static IAM access keys that never expire. Zero Trust requires short-lived tokens (< 1 hour). |
| **ZT-004** | No least-privilege: IAM user has `s3:*`, `ec2:*`, `rds:*` on `*`. Every action on every resource. |
| **ZT-005** | No device posture check. Is this request coming from an MDM-enrolled, patched laptop? Unknown. |

## The 5 Zero Trust Identity Violations

| Violation | Simple Explanation |
|-----------|-------------------|
| **ZT-ID-001** | TOTP (one-time password) window is 5 minutes instead of 30 seconds → replay attacks work |
| **ZT-ID-002** | Transferring $1M requires the *same* login token as viewing your profile — no step-up MFA |
| **ZT-ID-003** | Sessions never expire. A token from last month still works today |
| **ZT-ID-004** | JWT signature verification disabled. Attacker sets `alg:none` → any token is valid |
| **ZT-ID-005** | Sensitive data returned without checking device health (MDM enrollment, OS patch, EDR) |

## The JWT Algorithm Confusion Attack

```python
# ❌ BAD — Signature not verified at all
payload = jwt.decode(token, options={"verify_signature": False})

# ✅ GOOD — Verify with correct algorithm and secret
payload = jwt.decode(token, secret_key, algorithms=["HS256"])

# The Attack:
# Attacker takes any JWT → changes header to {"alg": "none"} → removes signature
# With "verify_signature: False", your server accepts any token with any claims!
# Result: attacker creates admin JWT for free
```

## Learn More
- [GLOSSARY.md](../GLOSSARY.md) → look up: Zero Trust, MFA, Least Privilege, JWT
- [NIST SP 800-207: Zero Trust Architecture](https://csrc.nist.gov/publications/detail/sp/800-207/final)
