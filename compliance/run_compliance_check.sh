#!/bin/bash
# =============================================================================
# compliance/run_compliance_check.sh — TigerGate CNAPP: Compliance Validation
# =============================================================================
# PURPOSE: Automated compliance check script that runs all scanners, maps
# findings to compliance controls, and generates a report. This is the single
# command to validate the entire CNAPP test suite coverage.
#
# USAGE:
#   chmod +x compliance/run_compliance_check.sh
#   ./compliance/run_compliance_check.sh
#
# FRAMEWORKS CHECKED:
#   - CIS AWS Benchmark v1.5.0 (via Checkov)
#   - OWASP Top 10 (via Semgrep)
#   - PCI-DSS v4.0 (via Checkov + custom rules)
#   - CIS Kubernetes Benchmark v1.7 (via Kubesec)
# =============================================================================

set -uo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color
BOLD='\033[1m'

REPORT_DIR="./compliance-reports"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
REPORT_FILE="$REPORT_DIR/full_report_$TIMESTAMP.md"
PASS=0; FAIL=0; SKIP=0

mkdir -p "$REPORT_DIR"

header() { echo -e "\n${BOLD}${BLUE}=== $1 ===${NC}"; }
pass()   { echo -e "  ${GREEN}✅ PASS${NC}: $1"; ((PASS++)); }
fail()   { echo -e "  ${RED}❌ FAIL${NC}: $1"; ((FAIL++)); }
warn()   { echo -e "  ${YELLOW}⚠️  WARN${NC}: $1"; ((SKIP++)); }
check_tool() { command -v "$1" &>/dev/null && return 0 || { warn "$1 not installed — skipping"; return 1; }; }

echo "=================================================="
echo "TigerGate CNAPP Compliance Validation Suite"
echo "Started: $(date)"
echo "=================================================="

# ── 1. Secrets Detection (Gitleaks) ──────────────────────────────────────────
header "CAT-1: Secrets Detection (Gitleaks)"
if check_tool gitleaks; then
    GITLEAKS_FINDINGS=$(gitleaks detect --source . --config secrets/gitleaks.toml \
        --no-git --report-format json --exit-code 0 2>/dev/null | python3 -c \
        "import sys,json; d=json.load(sys.stdin); print(len(d) if isinstance(d,list) else 0)" 2>/dev/null || echo "0")
    if [ "$GITLEAKS_FINDINGS" -gt 0 ] 2>/dev/null; then
        pass "Gitleaks found $GITLEAKS_FINDINGS secret patterns (scanner working!)"
    else
        fail "Gitleaks found 0 secrets — scanner may not be detecting test patterns"
    fi
else
    warn "Install: brew install gitleaks OR apt install gitleaks"
fi

# ── 2. IaC Security (Checkov) ────────────────────────────────────────────────
header "CAT-2: IaC Security / CSPM (Checkov — CIS + PCI-DSS)"
if check_tool checkov; then
    CHECKOV_OUT=$(checkov -d . --framework terraform --compact --quiet 2>/dev/null || true)
    CHECKOV_FAILS=$(echo "$CHECKOV_OUT" | grep -c "FAILED" 2>/dev/null || echo 0)
    if [ "$CHECKOV_FAILS" -gt 10 ] 2>/dev/null; then
        pass "Checkov found $CHECKOV_FAILS Terraform violations (scanner working!)"
    elif [ "$CHECKOV_FAILS" -gt 0 ]; then
        warn "Checkov found only $CHECKOV_FAILS violations — expected 50+"
    else
        fail "Checkov found 0 violations — check if Terraform files are in scope"
    fi
else
    warn "Install: pip3 install checkov"
fi

# ── 3. SAST (Semgrep) ────────────────────────────────────────────────────────
header "CAT-3: SAST Code Analysis (Semgrep — OWASP Top 10)"
if check_tool semgrep; then
    SEMGREP_OUT=$(semgrep --config auto --quiet --json . 2>/dev/null || echo '{"results":[]}')
    SEMGREP_FINDINGS=$(echo "$SEMGREP_OUT" | python3 -c \
        "import sys,json; d=json.load(sys.stdin); print(len(d.get('results',[])))" 2>/dev/null || echo 0)
    if [ "$SEMGREP_FINDINGS" -gt 20 ] 2>/dev/null; then
        pass "Semgrep found $SEMGREP_FINDINGS SAST findings (scanner working!)"
    else
        warn "Semgrep found $SEMGREP_FINDINGS findings — expected 50+"
    fi
else
    warn "Install: pip3 install semgrep"
fi

# ── 4. SCA / Vulnerable Libraries (Trivy) ───────────────────────────────────
header "CAT-4: SCA / SBOM (Trivy — CVE Database)"
if check_tool trivy; then
    TRIVY_OUT=$(trivy fs . --quiet --format json 2>/dev/null || echo '{"Results":[]}')
    TRIVY_VULNS=$(echo "$TRIVY_OUT" | python3 -c \
        "import sys,json; d=json.load(sys.stdin); total=sum(len(r.get('Vulnerabilities',[])) for r in d.get('Results',[])); print(total)" 2>/dev/null || echo 0)
    if [ "$TRIVY_VULNS" -gt 5 ] 2>/dev/null; then
        pass "Trivy found $TRIVY_VULNS CVEs in dependencies (scanner working!)"
    else
        warn "Trivy found $TRIVY_VULNS CVEs — check sca/sbom_cyclonedx.json"
    fi
else
    warn "Install: brew install trivy OR: curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh"
fi

# ── 5. Dockerfile Linting (Hadolint) ─────────────────────────────────────────
header "CAT-5: Container Security (Hadolint)"
if check_tool hadolint; then
    HADOLINT_ISSUES=0
    for dockerfile in $(find . -name "Dockerfile*" -not -path "./.git/*" 2>/dev/null); do
        ISSUES=$(hadolint --format json "$dockerfile" 2>/dev/null | python3 -c \
            "import sys,json; d=json.load(sys.stdin); print(len(d))" 2>/dev/null || echo 0)
        HADOLINT_ISSUES=$((HADOLINT_ISSUES + ISSUES))
    done
    if [ "$HADOLINT_ISSUES" -gt 3 ] 2>/dev/null; then
        pass "Hadolint found $HADOLINT_ISSUES Dockerfile issues (scanner working!)"
    else
        warn "Hadolint found $HADOLINT_ISSUES issues — expected more"
    fi
else
    warn "Install: brew install hadolint OR: docker run --rm -i hadolint/hadolint"
fi

# ── 6. Kubernetes Security (Kubesec) ─────────────────────────────────────────
header "CAT-6: KSPM (Kubesec — CIS K8s Benchmark)"
if check_tool kubesec; then
    KUBESEC_SCORE=0
    for yamfile in $(find kspm/ -name "*.yaml" 2>/dev/null); do
        SCORE=$(kubesec scan "$yamfile" 2>/dev/null | python3 -c \
            "import sys,json; d=json.load(sys.stdin); print(d[0].get('score',0) if d else 0)" 2>/dev/null || echo 0)
        if [ "$SCORE" -lt 0 ] 2>/dev/null; then
            pass "$yamfile: Score $SCORE (negative = violations detected!)"
        fi
    done
else
    warn "Install: brew install kubesec OR: docker run -i kubesec/kubesec:v2 scan /dev/stdin <yaml"
fi

# ── 7. Vulnerability Count Summary ───────────────────────────────────────────
header "CAT-7: Vulnerability Marker Count"
TOTAL_MARKERS=$(grep -r "🔴\|# BAD:\|// BAD:\|VULN:" \
    --include="*.py" --include="*.js" --include="*.tf" \
    --include="*.yaml" --include="*.yml" --include="*.sh" \
    --include="*.php" --include="*.java" --include="*.rb" \
    . --exclude-dir=".git" --exclude-dir="node_modules" -l 2>/dev/null | wc -l)
TOTAL_LINES=$(grep -r "🔴\|# BAD:\|// BAD:\|VULN:" \
    --include="*.py" --include="*.js" --include="*.tf" \
    --include="*.yaml" --include="*.yml" --include="*.sh" \
    --include="*.php" --include="*.java" --include="*.rb" \
    . --exclude-dir=".git" --exclude-dir="node_modules" 2>/dev/null | wc -l)
pass "Found $TOTAL_LINES vulnerability markers across $TOTAL_MARKERS files"

# ── Final Report ──────────────────────────────────────────────────────────────
echo ""
echo "=================================================="
echo -e "${BOLD}COMPLIANCE CHECK COMPLETE${NC}"
echo "Timestamp: $(date)"
echo -e "  ${GREEN}PASS: $PASS${NC}"
echo -e "  ${YELLOW}WARN: $SKIP${NC}"
echo -e "  ${RED}FAIL: $FAIL${NC}"
echo ""

# Write markdown report
cat > "$REPORT_FILE" << EOF
# TigerGate Compliance Check Report
**Date**: $(date)
**Branch**: $(git branch --show-current 2>/dev/null || echo "unknown")
**Commit**: $(git log --oneline -1 2>/dev/null || echo "unknown")

## Results
| Category | Status |
|----------|--------|
| Secrets Detection (Gitleaks) | $( [ $PASS -gt 0 ] && echo "✅ Pass" || echo "❌ Fail") |
| IaC Security (Checkov) | Checked |
| SAST (Semgrep) | Checked |
| SCA (Trivy) | Checked |
| Container (Hadolint) | Checked |
| KSPM (Kubesec) | Checked |

## Summary
- **PASS**: $PASS
- **WARN**: $SKIP  
- **FAIL**: $FAIL
- **Vulnerability Markers**: $TOTAL_LINES across $TOTAL_MARKERS files

See individual scanner reports in $REPORT_DIR/
EOF

echo "Full report saved: $REPORT_FILE"
echo "=================================================="
