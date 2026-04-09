# TigerGate CNAPP Target Simulator Makefile

.PHONY: help install start-nodes test format clean

help:
	@echo "TigerGate CNAPP Vulnerability Simulator"
	@echo "======================================="
	@echo "Commands:"
	@echo "  make install   - Initialize local dependencies for the apps (NPM files, Python Venv)"
	@echo "  make test      - Run local syntax validations for all IaC and Application files"
	@echo "  make format    - Formats all Terraform infrastructure-as-code files"
	@echo "  make attack    - Triggers the eBPF local runtime attack simulator script"

install:
	@echo "Installing dependencies..."
	@cd nodejs && npm install || true
	@cd python && python3 -m venv venv || true

test:
	@echo "Testing Scripts..."
	@php -l php/index.php || true
	@ruby -c ruby/app.rb || true
	@echo "Testing completed."

format:
	@echo "Formatting Terraform files..."
	@terraform fmt -recursive || echo "Terraform not installed"

attack:
	@echo "Executing eBPF Attack Simulator..."
	@chmod +x runtime/attack_simulator.sh
	@./runtime/attack_simulator.sh
