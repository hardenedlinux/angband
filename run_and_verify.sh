#!/bin/bash

# Configuration
SSH_PORT=2222
SSH_KEY=".ssh_key"
SSH_USER="ubuntu"
SSH_OPTS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5 -i $SSH_KEY"
QEMU_PID_FILE="harness/qemu.pid"
EXPLOIT_LOG="exploit_run.log"

echo "[Angband] Automated Execution and Verification"

# 1. Generate the exploit
echo "[*] Step 1: Generating and compiling the exploit..."
PYTHONPATH=/home/john /home/john/angband/venv/bin/python3 cli.py generate
if [ $? -ne 0 ]; then
    echo "[!] Failed to generate/compile exploit. Aborting."
    exit 1
fi

# 2. Wait for QEMU to be ready
echo "[*] Step 2: Waiting for VM to boot and accept SSH connections..."
retries=30
while [ $retries -gt 0 ]; do
    if ssh $SSH_OPTS -p $SSH_PORT $SSH_USER@localhost "echo 'VM Ready'" >/dev/null 2>&1; then
        echo "[+] VM is ready."
        break
    fi
    sleep 2
    ((retries--))
done

if [ $retries -eq 0 ]; then
    echo "[!] Timeout waiting for VM. Ensure QEMU is running."
    exit 1
fi

# Wait an extra few seconds for cloud-init to mount the 9p filesystem
echo "[*] Waiting for 9p filesystem mount..."
sleep 10 

# 3. Transfer and execute the exploit
echo "[*] Step 3: Installing kernel headers and build tools inside VM (if needed)..."
ssh $SSH_OPTS -p $SSH_PORT $SSH_USER@localhost "sudo apt-get update -y && sudo DEBIAN_FRONTEND=noninteractive apt-get install -y build-essential flex bison linux-headers-\$(uname -r)"

echo "[*] Step 4: Compiling module and executing the exploit inside the VM..."
echo "--- EXPLOIT EXECUTION LOG ---" > $EXPLOIT_LOG

# The 9p mount makes the exploit binary available at /mnt/angband/exploit
# We run it and collect the output
ssh $SSH_OPTS -p $SSH_PORT $SSH_USER@localhost "sudo mkdir -p /mnt/angband && sudo mount -t 9p -o trans=virtio,version=9p2000.L host0 /mnt/angband || true && cd /mnt/angband/module/vuln_drill && sudo make && sudo insmod vuln_drill.ko || true && cd /mnt/angband && sudo chmod +x exploit && ./exploit" 2>&1 | tee -a $EXPLOIT_LOG

# 5. Verification and Log Collection
echo "[*] Step 5: Verification and Log Collection..."
if grep -q "Success!" $EXPLOIT_LOG; then
    echo "[+] SUCCESS: Exploit reached root!"
elif grep -q "Attempted safe cleanup" $EXPLOIT_LOG; then
    echo "[-] FAILURE: Exploit failed but cleaned up safely."
else
    echo "[!] CRITICAL: Exploit failed and did not clean up cleanly, or crashed the kernel."
fi

# Fetch kernel logs (dmesg) to analyze
echo "[*] Fetching kernel dmesg logs for analysis..."
ssh $SSH_OPTS -p $SSH_PORT $SSH_USER@localhost "sudo dmesg | tail -n 50" > dmesg_tail.log

echo "[*] Verification complete. Check $EXPLOIT_LOG and dmesg_tail.log for details."
