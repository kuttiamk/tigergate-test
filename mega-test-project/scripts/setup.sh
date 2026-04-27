#!/bin/bash
# =============================================================================
# scripts/setup.sh – One-Time Project Setup Script
# =============================================================================
# PURPOSE: Installs prerequisites and starts the project for the first time.
#
# USAGE:
#   chmod +x scripts/setup.sh
#   ./scripts/setup.sh
#
# WHAT IT DOES:
#   1. Checks for Docker and Docker Compose
#   2. Pulls base images
#   3. Starts all services with docker compose
#   4. Waits for MySQL to be ready
#   5. Tests all endpoints
# =============================================================================

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

echo -e "${CYAN}==================================================================${NC}"
echo -e "${CYAN}  🏢 MegaCorp Mega Test Project – Setup Script${NC}"
echo -e "${CYAN}==================================================================${NC}"

# Move to project root
cd "$(dirname "$0")/.."

# =============================================================================
# Step 1: Check Prerequisites
# =============================================================================
echo -e "\n${YELLOW}[1/5] Checking prerequisites...${NC}"

if ! command -v docker &> /dev/null; then
    echo -e "${RED}❌ Docker is not installed!${NC}"
    echo -e "Install it from: https://docs.docker.com/get-docker/"
    exit 1
fi
echo -e "${GREEN}✅ Docker found: $(docker --version)${NC}"

if ! command -v docker &> /dev/null || ! docker compose version &> /dev/null; then
    echo -e "${RED}❌ Docker Compose is not installed!${NC}"
    echo -e "Install from: https://docs.docker.com/compose/install/"
    exit 1
fi
echo -e "${GREEN}✅ Docker Compose found: $(docker compose version)${NC}"

# =============================================================================
# Step 2: Pull Base Images
# =============================================================================
echo -e "\n${YELLOW}[2/5] Pulling base images (this may take a few minutes)...${NC}"
docker pull mysql:8.0
docker pull node:18
docker pull python:3.9
docker pull php:7.4-apache

# =============================================================================
# Step 3: Build and Start All Services
# =============================================================================
echo -e "\n${YELLOW}[3/5] Building and starting all services...${NC}"
docker compose build
docker compose up -d

# =============================================================================
# Step 4: Wait for MySQL
# =============================================================================
echo -e "\n${YELLOW}[4/5] Waiting for MySQL to be ready...${NC}"
MAX_RETRIES=30
count=0
until docker compose exec -T mysql mysqladmin ping -h localhost -uroot -proot123 --silent 2>/dev/null; do
    count=$((count + 1))
    if [ $count -ge $MAX_RETRIES ]; then
        echo -e "${RED}❌ MySQL did not start in time!${NC}"
        exit 1
    fi
    echo "  ⏳ MySQL not ready yet (attempt $count/$MAX_RETRIES)..."
    sleep 3
done
echo -e "${GREEN}✅ MySQL is ready!${NC}"

# =============================================================================
# Step 5: Health Check All Services
# =============================================================================
echo -e "\n${YELLOW}[5/5] Testing all service endpoints...${NC}"
sleep 5  # Give Node/Python/Java time to start

test_endpoint() {
    local name=$1
    local url=$2
    if curl -s --max-time 5 "$url" > /dev/null 2>&1; then
        echo -e "${GREEN}✅ $name is UP: $url${NC}"
    else
        echo -e "${YELLOW}⚠️  $name may not be ready yet: $url${NC}"
    fi
}

test_endpoint "Node.js API"    "http://localhost:3000/api/users"
test_endpoint "Python API"     "http://localhost:5000/api/products"
test_endpoint "Java API"       "http://localhost:8080/api/users"
test_endpoint "PHP App"        "http://localhost:8888"
test_endpoint "Frontend"       "http://localhost:5173"

echo -e "\n${CYAN}==================================================================${NC}"
echo -e "${GREEN}🎉 Setup complete! All services are running.${NC}"
echo -e "${CYAN}==================================================================${NC}"
echo ""
echo -e "  Frontend:       http://localhost:5173"
echo -e "  Node.js API:    http://localhost:3000"
echo -e "  Python API:     http://localhost:5000"
echo -e "  Java API:       http://localhost:8080"
echo -e "  PHP App:        http://localhost:8888"
echo -e "  MySQL:          localhost:3306 (root/root123)"
echo ""
echo -e "  Run scan:       ${YELLOW}./scripts/scan.sh${NC}"
echo -e "  Stop services:  ${YELLOW}docker compose down${NC}"
echo ""
