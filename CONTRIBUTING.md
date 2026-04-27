# 🤝 Contributing to TigerGate CNAPP Target Simulator

Thank you for helping make this security testing suite more comprehensive!

## Adding a New Vulnerability Module

1. **Choose the right directory** for your module based on the CNAPP pillar it targets:
   - Application SAST → `nodejs/`, `python/`, `php/`, `ruby/`, `java/`
   - Cloud Misconfigs → `cspm/`, `ciem/`
   - Kubernetes → `kspm/`
   - Runtime → `cwpp/runtime/`
   - Data Security → `dspm/`
   - AI/ML Security → `ai_spm/`

2. **File header format** — every file must include:
```python
# =============================================================================
# module/filename.py – TigerGate CNAPP Test: [Pillar Name]
# =============================================================================
# PURPOSE: Brief description of what this file demonstrates.
#
# VULNERABILITY FINDINGS:
#   VULN-001: Description (CWE-XXX) – Scanner: SonarQube SXXX
# =============================================================================
```

3. **Mark each intentional vulnerability** with one of the standard markers:
   - `🔴 VULN:` — for non-comment lines
   - `# BAD:` / `// BAD:` — for inline comments
   - `# VULN:` / `// VULN:` — for standalone comment lines

4. **Update the Makefile** `count-vulns` target if you add a new directory.

5. **Add a row** to the vulnerability matrix in `README.md`.

6. **Run tests before raising a PR:**
```bash
make test         # Syntax validation for all files
make count-vulns  # Verify marker count increased
```

## Style Guidelines

- Keep all comments educational — explain *why* it's vulnerable, not just that it is
- Reference the specific CWE, CVE, or framework rule that would catch it
- Use realistic-looking code (not toy examples)
- Never use actual production credentials — use the fake patterns defined in `secrets/`

## PR Checklist

- [ ] File header with purpose, pillar, and vulnerability list
- [ ] Every intentional vulnerability marked with standard marker
- [ ] CWE/CVE/SonarQube rule referenced in comment
- [ ] `make test` passes (syntax valid)
- [ ] Vulnerability matrix in README updated
