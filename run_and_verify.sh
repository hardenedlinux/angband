#!/bin/bash
set -euo pipefail

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT="$SCRIPT_DIR"
RUNTIME_ROOT="$REPO_ROOT/mordor_run"
CURRENT_DIR="$RUNTIME_ROOT/current"
SSH_DIR="$RUNTIME_ROOT/ssh"
SSH_PORT=2222
SSH_KEY="$SSH_DIR/id_ed25519"
SSH_USER="ubuntu"
SSH_OPTS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5 -i $SSH_KEY"
EXPLOIT_LOG="$CURRENT_DIR/exploit_run.log"
DMESG_LOG="$CURRENT_DIR/dmesg_tail.log"
STATUS_LOG="$CURRENT_DIR/vuln_drill_status.log"
ANGBAND_BIN="$REPO_ROOT/venv/bin/angband"
EXPECTED_VULN_DRILL_STAGES=(prep groom trigger leak primitive escalate cleanup)

echo "[Angband] Exploit execution and verification"

if [ ! -x "$ANGBAND_BIN" ]; then
    echo "[!] Missing $ANGBAND_BIN. Create the virtual environment and run 'pip install -e .' first."
    exit 1
fi

mkdir -p "$CURRENT_DIR" "$SSH_DIR"

if [ ! -f "$CURRENT_DIR/exploit.yaml" ]; then
    echo "[*] No exploit.yaml found. Initializing demo scenario..."
    "$ANGBAND_BIN" init demo
fi

KERNEL_TARGET=$("$REPO_ROOT/venv/bin/python" - <<'PY'
import yaml
from pathlib import Path

config = yaml.safe_load(Path("mordor_run/current/exploit.yaml").read_text()) or {}
print(config.get("kernel_target", "none"))
PY
)

echo "[*] Step 1: Generating and compiling the exploit payload..."
"$ANGBAND_BIN" generate

echo "[*] Step 2: Waiting for VM to boot and accept SSH connections..."
retries=30
while [ "$retries" -gt 0 ]; do
    if ssh $SSH_OPTS -p $SSH_PORT $SSH_USER@localhost "echo VM Ready" >/dev/null 2>&1; then
        echo "[+] VM is ready."
        break
    fi
    sleep 2
    retries=$((retries - 1))
done

if [ "$retries" -eq 0 ]; then
    echo "[!] Timeout waiting for VM. Start it with 'harness/launch.sh' after running 'harness/setup.sh'."
    exit 1
fi

echo "[*] Step 3: Running the exploit inside the VM..."
printf '%s\n' '--- DEMO EXECUTION LOG ---' > "$EXPLOIT_LOG"

if [ "$KERNEL_TARGET" = "vuln_drill" ]; then
    echo "[*] vuln_drill profile: building and loading the kernel module in the guest..."
    ssh $SSH_OPTS -p $SSH_PORT $SSH_USER@localhost "\
        sudo mkdir -p /mnt/angband && \
        sudo mount -t 9p -o trans=virtio,version=9p2000.L host0 /mnt/angband 2>/dev/null || true && \
        if ! command -v make >/dev/null 2>&1 || [ ! -d /lib/modules/\$(uname -r)/build ]; then \
            sudo DEBIAN_FRONTEND=noninteractive apt-get update -y && \
            sudo DEBIAN_FRONTEND=noninteractive apt-get install -y build-essential flex bison linux-headers-\$(uname -r) make; \
        fi && \
        cd /mnt/angband/module/vuln_drill && \
        (make clean || true) && make && \
        sudo rmmod vuln_drill 2>/dev/null || true && \
        sudo insmod ./vuln_drill.ko && \
        echo 0 | sudo tee /proc/sys/kernel/kptr_restrict > /dev/null && \
        cd /mnt/angband/mordor_run/current && \
        chmod +x exploit && ./exploit" 2>&1 | tee -a "$EXPLOIT_LOG"
else
    echo "[*] Scenario does not require vuln_drill. Skipping guest kernel module setup."
    ssh $SSH_OPTS -p $SSH_PORT $SSH_USER@localhost "sudo mkdir -p /mnt/angband && sudo mount -t 9p -o trans=virtio,version=9p2000.L host0 /mnt/angband 2>/dev/null || true && cd /mnt/angband/mordor_run/current && chmod +x exploit && ./exploit" 2>&1 | tee -a "$EXPLOIT_LOG"
fi

echo "[*] Step 4: Collecting logs..."
if [ "$KERNEL_TARGET" = "vuln_drill" ]; then
    ssh $SSH_OPTS -p $SSH_PORT $SSH_USER@localhost "sudo dmesg | grep 'vuln_drill:'" > "$DMESG_LOG"
    ssh $SSH_OPTS -p $SSH_PORT $SSH_USER@localhost "cat /proc/vuln_drill" > "$STATUS_LOG"
else
    ssh $SSH_OPTS -p $SSH_PORT $SSH_USER@localhost "sudo dmesg | tail -n 50" > "$DMESG_LOG"
fi

if grep -q "EXPLOIT COMPLETE" "$EXPLOIT_LOG" || grep -q "DEMO COMPLETE" "$EXPLOIT_LOG"; then
    echo "[+] Exploit completed successfully."
else
    echo "[!] Exploit payload did not report completion. Check $EXPLOIT_LOG and $DMESG_LOG."
    exit 1
fi

# Check for privilege escalation success
if grep -q "PRIVILEGE ESCALATION SUCCESSFUL" "$EXPLOIT_LOG"; then
    echo "[+] PRIVILEGE ESCALATION VERIFIED -- exploit achieved uid=0"
fi

if [ "$KERNEL_TARGET" = "vuln_drill" ]; then
    for stage in "${EXPECTED_VULN_DRILL_STAGES[@]}"; do
        if ! grep -q "vuln_drill: stage ${stage} received" "$DMESG_LOG"; then
            echo "[!] Missing vuln_drill stage marker for '${stage}'. Check $DMESG_LOG."
            exit 1
        fi
    done
    if ! grep -q '^sequence_complete: yes$' "$STATUS_LOG"; then
        echo "[!] vuln_drill did not report a complete in-order stage sequence. Check $STATUS_LOG."
        exit 1
    fi
    if ! grep -q '^out_of_order: no$' "$STATUS_LOG"; then
        echo "[!] vuln_drill reported out-of-order stage activity. Check $STATUS_LOG."
        exit 1
    fi
    echo "[+] Verified vuln_drill stage markers in guest dmesg."
    if grep -q "ESCALATE SUCCESS" "$DMESG_LOG"; then
        echo "[+] Kernel confirms privilege escalation via vuln_drill."
    fi
fi

echo "[*] Verification complete. Check $EXPLOIT_LOG and $DMESG_LOG for details."
