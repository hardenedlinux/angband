#!/bin/bash
# ---------------------------------------------------------------
# harness/launch.sh -- Boot the QEMU test VM
#
# Boots the overlay snapshot created by setup.sh.  The base image
# is never modified; all guest writes go into the overlay.
#
# SSH access:  ssh -i mordor_run/ssh/id_ed25519 -p 2222 ubuntu@localhost
# Serial log:  tail -f mordor_run/harness/serial.log
# QEMU Monitor: telnet localhost 4445  (for 'info' commands)
# GDB:         localhost:1234
# ---------------------------------------------------------------
set -euo pipefail

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
RUNTIME_ROOT="$REPO_ROOT/mordor_run"
HARNESS_DIR="$RUNTIME_ROOT/harness"
OVERLAY_IMAGE="$HARNESS_DIR/disk.qcow2"
SEED="$HARNESS_DIR/seed.img"

# ------ Pre-flight checks ------

if [ ! -f "$OVERLAY_IMAGE" ]; then
    echo "[!] Overlay image not found: $OVERLAY_IMAGE"
    echo "    Run 'bash harness/setup.sh' first."
    exit 1
fi

if [ ! -f "$SEED" ]; then
    echo "[!] Seed image not found: $SEED"
    echo "    Run 'bash harness/setup.sh' first."
    exit 1
fi

# Check for existing instance
if [ -f "$HARNESS_DIR/qemu.pid" ]; then
    OLD_PID=$(cat "$HARNESS_DIR/qemu.pid")
    if kill -0 "$OLD_PID" 2>/dev/null; then
        echo "[!] QEMU is already running (PID $OLD_PID)."
        echo "    Stop it first:  bash harness/stop.sh"
        exit 1
    else
        # Stale PID file
        rm -f "$HARNESS_DIR/qemu.pid" "$HARNESS_DIR/qemu_wrapper.pid"
    fi
fi

# Check port availability
if ss -tlnp 2>/dev/null | grep -q ':2222\b'; then
    echo "[!] Port 2222 is already in use.  Another VM may be running."
    exit 1
fi

# ------ KVM detection ------

QEMU_ACCEL_ARGS=()
if [ -r /dev/kvm ] && [ -w /dev/kvm ]; then
    # Use host CPU with SMEP/SMAP disabled for the basic ret2usr exploit.
    # For SMEP/SMAP bypass exploits, change -smep,-smap to +smep,+smap.
    QEMU_ACCEL_ARGS=(-enable-kvm -cpu host,-smep,-smap)
    echo "[+] KVM acceleration enabled (SMEP/SMAP disabled for exploit dev)."
else
    # Software emulation: qemu64 without SMEP/SMAP
    QEMU_ACCEL_ARGS=(-cpu qemu64,-smep,-smap)
    echo "[*] KVM not available.  Using software emulation (slow)."
fi

# ------ Launch ------

mkdir -p "$HARNESS_DIR"

echo "[*] Launching QEMU VM..."
echo "    Overlay:  $OVERLAY_IMAGE"
echo "    SSH:      ssh -i mordor_run/ssh/id_ed25519 -p 2222 ubuntu@localhost"
echo "    Console:  telnet localhost 4444"

nohup qemu-system-x86_64 \
    "${QEMU_ACCEL_ARGS[@]}" \
    -m 4G \
    -smp 2 \
    -drive if=virtio,format=qcow2,file="$OVERLAY_IMAGE" \
    -drive if=virtio,format=raw,file="$SEED" \
    -net user,hostfwd=tcp::2222-:22 -net nic \
    -display none \
    -s \
    -virtfs local,path="$REPO_ROOT",mount_tag=host0,security_model=passthrough,id=host0 \
    -serial file:"$HARNESS_DIR/serial.log" \
    -monitor telnet:localhost:4445,server,nowait \
    -pidfile "$HARNESS_DIR/qemu.pid" \
    "$@" > "$HARNESS_DIR/qemu.log" 2>&1 &

echo $! > "$HARNESS_DIR/qemu_wrapper.pid"

# ------ Wait for SSH ------

echo ""
echo "[*] Waiting for VM to boot (first boot takes ~60-90s for cloud-init)..."

retries=45
while [ "$retries" -gt 0 ]; do
    if ssh -o StrictHostKeyChecking=no \
           -o UserKnownHostsFile=/dev/null \
           -o ConnectTimeout=2 \
           -o LogLevel=ERROR \
           -i "$RUNTIME_ROOT/ssh/id_ed25519" \
           -p 2222 ubuntu@localhost \
           "echo ok" >/dev/null 2>&1; then
        echo "[+] VM is ready!  SSH is up."
        echo ""
        echo "  Connect:  ssh -o StrictHostKeyChecking=no -i mordor_run/ssh/id_ed25519 -p 2222 ubuntu@localhost"
        echo ""
        exit 0
    fi
    printf "  [%2d/%d] waiting...\r" $((45 - retries + 1)) 45
    sleep 3
    retries=$((retries - 1))
done

echo ""
echo "[!] SSH did not become available within ~135 seconds."
echo "    The VM may still be booting.  Check: cat mordor_run/harness/qemu.log"
echo "    Or use the serial console:  bash harness/console.sh"
