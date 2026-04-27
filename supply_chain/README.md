# 📁 `supply_chain/` — Software Supply Chain Security

## What Is This?

A **supply chain attack** targets the tools and processes that build your software —
rather than the software itself. Famous examples:
- **SolarWinds (2020)**: Attackers inserted malware into software updates — 18,000 companies infected
- **XZ Utils (2024)**: A backdoor was nearly merged into a widely-used Linux compression library
- **Codecov (2021)**: Attackers modified a CI/CD script to steal environment variables (secrets) from every company using it

This folder simulates similar GitHub Actions supply chain attack vectors.

## What's In This Folder?

| File | What It Demonstrates |
|------|---------------------|
| `malicious_workflow.yml` | 6 GitHub Actions attack vectors |

## The 6 Supply Chain Attack Vectors

### SC-001: Unpinned Actions (Most Common!)
```yaml
# ❌ BAD — Anyone who controls the 'v3' tag can push malicious code
- uses: actions/checkout@v3

# ✅ GOOD — Pin to a specific SHA that can't be changed
- uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683  # v4.2.2
```

### SC-002: Self-Hosted Runners
Self-hosted runners are persistent machines. If one job's code is malicious, it can
leave files/backdoors on the runner that affect ALL future jobs.

### SC-003: Over-Permissioned GITHUB_TOKEN
```yaml
# ❌ BAD — CI pipeline can read ALL secrets, write to ALL repos
permissions:
  secrets: write
  contents: write

# ✅ GOOD — Minimal permissions
permissions:
  contents: read
```

### SC-004: Fork PRs Triggering Secrets
When `pull_request:` trigger runs code from a fork, that untrusted forker's code
runs with access to your repository's secrets.

### SC-005: Typosquatting
An attacker publishes `actions/setup-nodde` (not `node`) on the marketplace.
A typo in your workflow installs the malicious action.

### SC-006: Secrets in Global `env:`
Secrets defined at the workflow level are visible to ALL steps — including
third-party actions you didn't write.

## The Safe DevSecOps Pipeline

See [`../devsecops/shift_left_pipeline.yml`](../devsecops/shift_left_pipeline.yml)
for a properly secured CI/CD pipeline that avoids all these mistakes.

## Learn More
- [GLOSSARY.md](../GLOSSARY.md) → look up: Supply Chain Attack
- [GitHub Actions Security Hardening Guide](https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions)
