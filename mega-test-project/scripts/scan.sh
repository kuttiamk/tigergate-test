#!/bin/bash
# =============================================================================
# scripts/scan.sh – SonarQube Scan Script
# =============================================================================
# PURPOSE: Runs the SonarQube scanner against the entire monorepo.
#
# PRE-REQUISITES:
#   1. SonarQube server running at http://localhost:9000
#      Start SonarQube with Docker:
#        docker run -d --name sonarqube -p 9000:9000 sonarqube:community
#
#   2. Create a project and token at:
#        http://localhost:9000 → Login (admin/admin) → Create Project
#
#   3. Set your token:
#        export SONAR_TOKEN=your_token_here
#
# USAGE:
#   chmod +x scripts/scan.sh
#   export SONAR_TOKEN=your_token_here
#   ./scripts/scan.sh
# =============================================================================

set -e

CYAN='\033[0;36m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

cd "$(dirname "$0")/.."

echo -e "${CYAN}==================================================================${NC}"
echo -e "${CYAN}  📊 SonarQube SAST Scan – Mega Test Project${NC}"
echo -e "${CYAN}==================================================================${NC}"

SONAR_HOST=${SONAR_HOST_URL:-"http://localhost:9000"}

# Check token
if [ -z "$SONAR_TOKEN" ]; then
    echo -e "${RED}❌ SONAR_TOKEN is not set!${NC}"
    echo -e "  Run: ${YELLOW}export SONAR_TOKEN=your_sonar_token${NC}"
    echo -e "  Get token from: $SONAR_HOST → My Account → Security → Generate Token"
    exit 1
fi

# Check SonarQube is running
if ! curl -s --max-time 5 "$SONAR_HOST/api/system/status" > /dev/null 2>&1; then
    echo -e "${RED}❌ SonarQube is not running at $SONAR_HOST${NC}"
    echo -e "  Start it with:"
    echo -e "  ${YELLOW}docker run -d --name sonarqube -p 9000:9000 sonarqube:community${NC}"
    echo -e "  Wait 2-3 minutes for SonarQube to start, then run this script again."
    exit 1
fi

echo -e "${GREEN}✅ SonarQube is running at $SONAR_HOST${NC}"
echo -e "\n${YELLOW}Running scanner (this takes 1-3 minutes)...${NC}"

# =============================================================================
# Run SonarQube Scanner via Docker (no local installation needed!)
# =============================================================================
docker run --rm \
    --network host \
    -e SONAR_HOST_URL="$SONAR_HOST" \
    -e SONAR_TOKEN="$SONAR_TOKEN" \
    -v "$(pwd):/usr/src" \
    sonarsource/sonar-scanner-cli:5 \
    -Dsonar.projectKey=mega-test-project \
    -Dsonar.sources=frontend/src,backend-node,backend-python,vulnerable-php \
    -Dsonar.exclusions="**/node_modules/**,**/__pycache__/**,**/target/**,**/dist/**"

echo -e "\n${GREEN}✅ Scan complete!${NC}"
echo -e "View results at: ${CYAN}$SONAR_HOST/dashboard?id=mega-test-project${NC}"
echo ""
echo -e "What to look for:"
echo -e "  🔴 Vulnerabilities  – Security holes (SQL injection, XSS, etc.)"
echo -e "  🟡 Security Hotspots – Code that needs review"
echo -e "  🟠 Bugs             – Code that is likely wrong"
echo -e "  🔵 Code Smells      – Maintainability issues"
echo ""
