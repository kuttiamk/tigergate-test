# ===========================================================================
# TigerGate CNAPP Target Simulator – World-Class Makefile
# ===========================================================================
# Usage:
#   make help          – Show all available commands
#   make install       – Install all language dependencies
#   make start         – Start all services (Node.js, Python, Ruby, GraphQL)
#   make scan-all      – Run all security scanners
#   make attack        – Run runtime eBPF attack simulation
#   make test          – Run syntax validation for all source files
# ===========================================================================

.DEFAULT_GOAL := help
SHELL         := /bin/bash

# ── Colors ──────────────────────────────────────────────────────────────────
RED    := \033[0;31m
YELLOW := \033[1;33m
GREEN  := \033[0;32m
CYAN   := \033[0;36m
NC     := \033[0m

# ── Paths ────────────────────────────────────────────────────────────────────
ROOT_DIR   := $(shell pwd)
NODE_DIR   := $(ROOT_DIR)/nodejs
PYTHON_DIR := $(ROOT_DIR)/python
RUBY_DIR   := $(ROOT_DIR)/ruby
LOG_DIR    := $(ROOT_DIR)/.logs

# ── Banner ───────────────────────────────────────────────────────────────────
define BANNER
@echo -e "$(CYAN)"
@echo "  ████████╗██╗ ██████╗ ███████╗██████╗  ██████╗  █████╗ ████████╗███████╗"
@echo "     ██╔══╝██║██╔════╝ ██╔════╝██╔══██╗██╔════╝ ██╔══██╗╚══██╔══╝██╔════╝"
@echo "     ██║   ██║██║  ███╗█████╗  ██████╔╝██║  ███╗███████║   ██║   █████╗  "
@echo "     ██║   ██║██║   ██║██╔══╝  ██╔══██╗██║   ██║██╔══██║   ██║   ██╔══╝  "
@echo "     ██║   ██║╚██████╔╝███████╗██║  ██║╚██████╔╝██║  ██║   ██║   ███████╗"
@echo "     ╚═╝   ╚═╝ ╚═════╝ ╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚══════╝"
@echo -e "$(NC)"
endef

.PHONY: help install start stop test \
        scan-sonar scan-trivy scan-checkov scan-tfsec scan-hadolint scan-kubesec scan-all \
        attack clean count-vulns


# ════════════════════════════════════════════════════════════════════════════
# HELP
# ════════════════════════════════════════════════════════════════════════════
help:
	$(BANNER)
	@echo -e "$(YELLOW)  TigerGate CNAPP Target Simulator – Available Commands$(NC)"
	@echo -e "$(YELLOW)  ═══════════════════════════════════════════════════════$(NC)"
	@echo ""
	@echo -e "  $(GREEN)Setup$(NC)"
	@echo "    install          Install all language dependencies (Node.js, Python, Ruby)"
	@echo "    install-hooks    Install git pre-commit hooks (syntax + secret checks)"
	@echo "    clean            Remove generated files, logs, virtualenvs"
	@echo ""
	@echo -e "  $(GREEN)Development$(NC)"
	@echo "    start            Start all services in background"
	@echo "    start-node       Start Node.js Express server (port 3000)"
	@echo "    start-python     Start Python Flask server (port 5000)"
	@echo "    start-ruby       Start Ruby Sinatra server (port 4567)"
	@echo "    start-graphql    Start GraphQL Apollo server (port 4000)"
	@echo "    stop             Stop all running services"
	@echo "    test             Run syntax validation for all files"
	@echo "    open-dashboard   Open the HTML Security Coverage Dashboard"
	@echo ""
	@echo -e "  $(GREEN)Security Scanning$(NC)"
	@echo "    scan-sonar       Run SonarQube SAST scan (Docker-based)"
	@echo "    scan-trivy       Scan Docker images and SCA for CVEs"
	@echo "    scan-checkov     Run Checkov IaC misconfiguration scan"
	@echo "    scan-tfsec       Run tfsec Terraform security scan"
	@echo "    scan-hadolint    Lint all Dockerfiles with Hadolint"
	@echo "    scan-kubesec     Run kubesec on K8s manifests"
	@echo "    scan-gitleaks    Run Gitleaks secrets scanner"
	@echo "    scan-semgrep     Run Semgrep SAST (multi-language)"
	@echo "    scan-all         Run ALL scanners sequentially"
	@echo ""
	@echo -e "  $(GREEN)Runtime Testing$(NC)"
	@echo "    attack           Run eBPF runtime attack simulation (basic)"
	@echo "    attack-advanced  Run advanced CWPP attack simulation (T001–T005)"
	@echo "    count-vulns      Count total vulnerability markers across all files"
	@echo ""


# ════════════════════════════════════════════════════════════════════════════
# INSTALL
# ════════════════════════════════════════════════════════════════════════════
install:
	@echo -e "$(CYAN)[1/4] Installing Node.js dependencies...$(NC)"
	@cd $(NODE_DIR) && npm install --legacy-peer-deps 2>&1 | tail -3
	@echo ""

	@echo -e "$(CYAN)[2/4] Setting up Python virtualenv...$(NC)"
	@cd $(PYTHON_DIR) && python3 -m venv venv || true
	@cd $(PYTHON_DIR) && ./venv/bin/pip install -q flask pyyaml 2>&1 | tail -3
	@echo ""

	@echo -e "$(CYAN)[3/4] Installing Ruby Sinatra gem...$(NC)"
	@gem install sinatra sqlite3 --no-document 2>&1 | tail -3 || true
	@echo ""

	@echo -e "$(CYAN)[4/4] Creating log directory...$(NC)"
	@mkdir -p $(LOG_DIR)
	@echo -e "$(GREEN)✓ All dependencies installed.$(NC)"


# ════════════════════════════════════════════════════════════════════════════
# START / STOP SERVICES
# ════════════════════════════════════════════════════════════════════════════
start-node:
	@echo -e "$(CYAN)Starting Node.js Express server → http://localhost:3000$(NC)"
	@cd $(NODE_DIR) && nohup node server.js > $(LOG_DIR)/node.log 2>&1 &
	@echo "  PID: $$!"
	@sleep 1 && curl -s http://localhost:3000/api/users?search=admin | head -c 100 || true

start-python:
	@echo -e "$(CYAN)Starting Python Flask server → http://localhost:5000$(NC)"
	@cd $(PYTHON_DIR) && nohup ./venv/bin/python app.py > $(LOG_DIR)/python.log 2>&1 &
	@echo "  PID: $$!"

start-ruby:
	@echo -e "$(CYAN)Starting Ruby Sinatra server → http://localhost:4567$(NC)"
	@cd $(ROOT_DIR) && nohup ruby ruby/app.rb > $(LOG_DIR)/ruby.log 2>&1 &
	@echo "  PID: $$!"

start-graphql:
	@echo -e "$(CYAN)Starting GraphQL Apollo server → http://localhost:4000$(NC)"
	@cd $(ROOT_DIR)/api && nohup node graphql_server.js > $(LOG_DIR)/graphql.log 2>&1 &
	@echo "  PID: $$!"

start: start-node start-python start-ruby start-graphql
	@echo ""
	@echo -e "$(GREEN)✓ All services started.$(NC)"
	@echo "  Node.js  → http://localhost:3000"
	@echo "  Python   → http://localhost:5000"
	@echo "  Ruby     → http://localhost:4567"
	@echo "  GraphQL  → http://localhost:4000"

stop:
	@echo -e "$(YELLOW)Stopping all services...$(NC)"
	@pkill -f "node server.js"   2>/dev/null && echo "  ✓ Node.js stopped"   || true
	@pkill -f "python app.py"    2>/dev/null && echo "  ✓ Python stopped"    || true
	@pkill -f "ruby app.rb"      2>/dev/null && echo "  ✓ Ruby stopped"      || true
	@pkill -f "graphql_server"   2>/dev/null && echo "  ✓ GraphQL stopped"   || true
	@echo -e "$(GREEN)Done.$(NC)"


# ════════════════════════════════════════════════════════════════════════════
# TESTING
# ════════════════════════════════════════════════════════════════════════════
test:
	@echo -e "$(CYAN)Running syntax validation for all files...$(NC)"
	@echo ""
	@echo "  [Node.js] Checking server.js..."
	@node --check nodejs/server.js && echo "    ✓ Node.js: OK" || echo "    ✗ Node.js: FAILED"

	@echo "  [Python]  Checking app.py..."
	@python3 -m py_compile python/app.py && echo "    ✓ Python: OK" || echo "    ✗ Python: FAILED"

	@echo "  [PHP]     Checking index.php..."
	@php -l php/index.php 2>&1 | tail -1 && echo "    ✓ PHP: OK" || echo "    ✗ PHP: FAILED"

	@echo "  [Ruby]    Checking app.rb..."
	@ruby -c ruby/app.rb && echo "    ✓ Ruby: OK" || echo "    ✗ Ruby: FAILED"

	@echo "  [Java]    Checking VulnerableApp.java..."
	@javac -nowarn java/VulnerableApp.java -d /tmp/java_check 2>&1 | head -3 || true

	@echo "  [Bash]    Checking attack_simulator.sh..."
	@bash -n runtime/attack_simulator.sh && echo "    ✓ Bash: OK" || echo "    ✗ Bash: FAILED"

	@echo "  [HCL]     Validating Terraform files..."
	@terraform fmt -check -recursive cspm/ iac/ 2>&1 | head -5 || echo "    (terraform not installed)"

	@echo "  [YAML]    Validating K8s manifests..."
	@python3 -c "import yaml; [yaml.safe_load(open(f)) for f in ['kspm/vulnerable_deployment.yaml']]" \
	    && echo "    ✓ YAML: OK" || echo "    ✗ YAML: FAILED"

	@echo ""
	@echo -e "$(GREEN)✓ Validation complete.$(NC)"


# ════════════════════════════════════════════════════════════════════════════
# SECURITY SCANNERS
# ════════════════════════════════════════════════════════════════════════════

# SonarQube SAST Scan (Docker-based, no local install needed)
scan-sonar:
	@echo -e "$(CYAN)Running SonarQube SAST scan...$(NC)"
	@[ -f sonar-project.properties ] || (echo "ERROR: sonar-project.properties not found" && exit 1)
	@echo "  Requires: SONAR_HOST_URL and SONAR_TOKEN environment variables"
	@docker run --rm \
	    -e SONAR_HOST_URL="$${SONAR_HOST_URL:-http://localhost:9000}" \
	    -e SONAR_TOKEN="$${SONAR_TOKEN:-}" \
	    -v $(ROOT_DIR):/usr/src \
	    sonarsource/sonar-scanner-cli:latest
	@echo -e "$(GREEN)✓ SonarQube scan complete. Check your SonarQube dashboard.$(NC)"

# Trivy – Container CVE Scanning
scan-trivy:
	@echo -e "$(CYAN)Running Trivy container scan...$(NC)"
	@command -v trivy >/dev/null 2>&1 || (echo "Installing Trivy..." && \
	    docker pull aquasec/trivy:latest)
	@docker run --rm -v /var/run/docker.sock:/var/run/docker.sock aquasec/trivy:latest \
	    image --severity HIGH,CRITICAL nginx:1.14.2 || true
	@echo -e "$(GREEN)✓ Trivy scan complete.$(NC)"

# Checkov – IaC (Terraform) Misconfiguration Scan
scan-checkov:
	@echo -e "$(CYAN)Running Checkov IaC scan on cspm/ and iac/...$(NC)"
	@docker run --rm -v $(ROOT_DIR):/src \
	    bridgecrew/checkov:latest \
	    --directory /src/cspm \
	    --output cli \
	    --compact \
	    --quiet || true
	@docker run --rm -v $(ROOT_DIR):/src \
	    bridgecrew/checkov:latest \
	    --directory /src/ciem \
	    --output cli \
	    --compact \
	    --quiet || true
	@echo -e "$(GREEN)✓ Checkov scan complete.$(NC)"

# tfsec – Terraform Security Scan
scan-tfsec:
	@echo -e "$(CYAN)Running tfsec on Terraform files...$(NC)"
	@docker run --rm -v $(ROOT_DIR):/src aquasec/tfsec:latest /src/cspm || true
	@docker run --rm -v $(ROOT_DIR):/src aquasec/tfsec:latest /src/ciem || true
	@echo -e "$(GREEN)✓ tfsec scan complete.$(NC)"

# Hadolint – Dockerfile Linting
scan-hadolint:
	@echo -e "$(CYAN)Running Hadolint on all Dockerfiles...$(NC)"
	@for df in $$(find . -name "Dockerfile*" -not -path "./.git/*"); do \
	    echo "  Linting: $$df"; \
	    docker run --rm -i hadolint/hadolint < "$$df" || true; \
	done
	@echo -e "$(GREEN)✓ Hadolint scan complete.$(NC)"

# kubesec – Kubernetes Manifest Security Scan
scan-kubesec:
	@echo -e "$(CYAN)Running kubesec on K8s manifests...$(NC)"
	@docker run --rm -i kubesec/kubesec:v2 scan /dev/stdin \
	    < kspm/vulnerable_deployment.yaml || true
	@echo -e "$(GREEN)✓ kubesec scan complete.$(NC)"

# Run ALL scanners
scan-all: scan-checkov scan-tfsec scan-hadolint scan-kubesec
	@echo ""
	@echo -e "$(GREEN)════════════════════════════════════════════$(NC)"
	@echo -e "$(GREEN)  All security scans complete!$(NC)"
	@echo -e "$(GREEN)════════════════════════════════════════════$(NC)"
	@$(MAKE) count-vulns


# ════════════════════════════════════════════════════════════════════════════
# RUNTIME ATTACK SIMULATION
# ════════════════════════════════════════════════════════════════════════════
attack:
	@echo -e "$(RED)WARNING: This simulates runtime attack patterns for testing purposes only.$(NC)"
	@echo -e "$(YELLOW)TigerGate CWPP eBPF sensors should fire for each technique.$(NC)"
	@echo ""
	@chmod +x runtime/attack_simulator.sh
	@bash runtime/attack_simulator.sh


# ════════════════════════════════════════════════════════════════════════════
# UTILITIES
# ════════════════════════════════════════════════════════════════════════════

# Count vulnerability markers across all source files
count-vulns:
	@echo -e "$(CYAN)Counting vulnerability markers (🔴 / # VULN: / // VULN:)...$(NC)"
	@echo ""
	@echo "  File breakdown:"
	@for f in nodejs/server.js python/app.py php/index.php ruby/app.rb java/VulnerableApp.java \
	          api/graphql_server.js cspm/aws_insecure.tf cspm/azure_insecure.tf cspm/gcp_insecure.tf \
	          ciem/overly_permissive_iam.tf kspm/vulnerable_deployment.yaml \
	          runtime/attack_simulator.sh sast_advanced/ssti_jinja.py sast_advanced/deserialization_gadget.js; do \
	    COUNT=$$(grep -c "🔴\|# VULN:\|// VULN:\|# BAD:\|// BAD:" "$$f" 2>/dev/null || echo 0); \
	    printf "    %-50s %3d markers\n" "$$f" "$$COUNT"; \
	done
	@echo ""
	@TOTAL=$$(grep -r "🔴\|# VULN:\|// VULN:\|# BAD:\|// BAD:" \
	    nodejs/ python/ php/ ruby/ java/ api/ cspm/ ciem/ kspm/ runtime/ sast_advanced/ \
	    --include="*.js" --include="*.py" --include="*.php" --include="*.rb" \
	    --include="*.java" --include="*.tf" --include="*.yaml" --include="*.sh" \
	    2>/dev/null | wc -l); \
	echo -e "  $(GREEN)Total vulnerability markers: $$TOTAL$(NC)"

format:
	@echo -e "$(CYAN)Formatting Terraform files...$(NC)"
	@terraform fmt -recursive cspm/ ciem/ iac/ 2>/dev/null || echo "  terraform not installed"
	@echo -e "$(GREEN)✓ Done.$(NC)"

clean:
	@echo -e "$(YELLOW)Cleaning up...$(NC)"
	@rm -rf $(LOG_DIR) .scannerwork .sonar
	@rm -rf nodejs/node_modules python/venv
	@rm -f java/*.class java/__pycache__
	@find . -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true
	@find . -name "*.pyc" -delete 2>/dev/null || true
	@echo -e "$(GREEN)✓ Clean complete.$(NC)"


# ════════════════════════════════════════════════════════════════════════════
# GIT HOOKS
# ════════════════════════════════════════════════════════════════════════════
install-hooks:
	@echo -e "$(CYAN)Installing pre-commit hooks...$(NC)"
	@cp hooks/pre-commit .git/hooks/pre-commit
	@chmod +x .git/hooks/pre-commit
	@echo -e "$(GREEN)✓ Pre-commit hook installed. Will run on every commit.$(NC)"

# ════════════════════════════════════════════════════════════════════════════
# DASHBOARD
# ════════════════════════════════════════════════════════════════════════════
open-dashboard:
	@echo -e "$(CYAN)Opening Security Coverage Dashboard...$(NC)"
	@xdg-open dashboard.html 2>/dev/null || open dashboard.html 2>/dev/null || \
    echo "Open dashboard.html in your browser: file://$(ROOT_DIR)/dashboard.html"

# ════════════════════════════════════════════════════════════════════════════
# ADDITIONAL SCANNERS
# ════════════════════════════════════════════════════════════════════════════
scan-gitleaks:
	@echo -e "$(CYAN)Running Gitleaks secrets scanner...$(NC)"
	@docker run --rm -v $(ROOT_DIR):/path \
	    zricethezav/gitleaks:latest detect --source=/path -v --no-git || true
	@echo -e "$(GREEN)✓ Gitleaks scan complete.$(NC)"

scan-semgrep:
	@echo -e "$(CYAN)Running Semgrep SAST (multi-language)...$(NC)"
	@docker run --rm \
	    -v $(ROOT_DIR):/src \
	    semgrep/semgrep:latest semgrep \
	    --config auto \
	    --severity ERROR \
	    --output /dev/stdout \
	    /src/nodejs /src/python /src/php /src/sast_advanced || true
	@echo -e "$(GREEN)✓ Semgrep scan complete.$(NC)"

scan-trivy-sca:
	@echo -e "$(CYAN)Running Trivy SCA (package vulnerability scan)...$(NC)"
	@docker run --rm -v $(ROOT_DIR):/src \
	    aquasec/trivy:latest fs /src/sca \
	    --severity HIGH,CRITICAL \
	    --format table || true
	@echo -e "$(GREEN)✓ Trivy SCA scan complete.$(NC)"

attack-advanced:
	@echo -e "$(RED)WARNING: Running advanced CWPP attack simulation (T001–T005).$(NC)"
	@echo -e "$(YELLOW)TigerGate eBPF sensors should fire – docker socket, DNS tunnel, cron, miner patterns.$(NC)"
	@chmod +x cwpp/runtime/runtime_attack_advanced.sh
	@bash cwpp/runtime/runtime_attack_advanced.sh

# Override scan-all to include all new scanners
scan-all: scan-checkov scan-tfsec scan-hadolint scan-kubesec scan-gitleaks scan-trivy-sca
	@echo ""
	@echo -e "$(GREEN)════════════════════════════════════════════════════════════$(NC)"
	@echo -e "$(GREEN)  All security scans complete! Check results above.$(NC)"
	@echo -e "$(GREEN)════════════════════════════════════════════════════════════$(NC)"
	@$(MAKE) count-vulns

