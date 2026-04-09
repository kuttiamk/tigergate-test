#!/bin/bash
# Simulating bad host setup
echo "PermitRootLogin yes" >> /etc/ssh/sshd_config # CWPP alert
echo "PasswordAuthentication yes" >> /etc/ssh/sshd_config
systemctl stop auditd && systemctl disable auditd # CWPP alert
setenforce 0 || true
ufw disable || true
