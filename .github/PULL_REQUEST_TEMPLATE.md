# =============================================================================
# .github/PULL_REQUEST_TEMPLATE.md – TigerGate CNAPP Test: PR Governance
# =============================================================================
# PURPOSE: A PR template with intentionally weak security checklists.
# This triggers governance gap detections in CNAPP platforms.
# =============================================================================

## 🔄 Pull Request Summary

**What does this PR do?**
<!-- Describe the change -->

**Related Issue:** Fixes #

---

## ✅ Checklist (INTENTIONALLY INCOMPLETE)

- [ ] Code reviewed by at least 1 team member
<!-- 🔴 VULN: Only 1 reviewer required even for critical infra changes -->

- [ ] Tests added or updated

<!-- 🔴 VULN: MISSING required checks below (intentional governance gap):
  - [ ] Security review for changes to IaC / Terraform
  - [ ] Secret scanning passed (no credentials committed)
  - [ ] SAST scan passed (no new critical vulns introduced)
  - [ ] Peer review from security team for CIEM/KSPM changes
-->

- [ ] Docs updated (if needed)
