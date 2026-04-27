#!/bin/bash
# ---------------------------------------------------------------
# harness/reset.sh -- Reset the VM to a clean state (instant)
#
# Stops the running VM, destroys the overlay snapshot, and creates
# a fresh one from the base image.  Also regenerates the cloud-init
# seed so the new overlay gets properly provisioned on next boot.
#
# The base image in cache/ is never re-downloaded.
# ---------------------------------------------------------------
set -euo pipefail

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
RUNTIME_ROOT="$REPO_ROOT/mordor_run"
CACHE_DIR="$RUNTIME_ROOT/cache"
HARNESS_DIR="$RUNTIME_ROOT/harness"
SSH_DIR="$RUNTIME_ROOT/ssh"
BASE_IMAGE="$CACHE_DIR/ubuntu-24.04-server-cloudimg-amd64.img"
OVERLAY_IMAGE="$HARNESS_DIR/disk.qcow2"
SSH_KEY="$SSH_DIR/id_ed25519"

echo "[Angband] Resetting VM to clean state..."

# ------ Stop running VM if any ------

if [ -f "$HARNESS_DIR/qemu.pid" ]; then
    PID=$(cat "$HARNESS_DIR/qemu.pid")
    if kill -0 "$PID" 2>/dev/null; then
        echo "[*] Stopping running VM (PID $PID)..."
        bash "$SCRIPT_DIR/stop.sh"
    fi
fi

# ------ Verify base image exists ------

if [ ! -f "$BASE_IMAGE" ]; then
    echo "[!] Base image not found.  Run 'bash harness/setup.sh' first."
    exit 1
fi

if [ ! -f "$SSH_KEY" ]; then
    echo "[!] SSH key not found.  Run 'bash harness/setup.sh' first."
    exit 1
fi

# ------ Recreate overlay ------

echo "[*] Destroying old overlay..."
rm -f "$OVERLAY_IMAGE"

echo "[*] Creating fresh overlay..."
qemu-img create -f qcow2 -b "$BASE_IMAGE" -F qcow2 "$OVERLAY_IMAGE" 10G >/dev/null 2>&1

# ------ Recreate seed (new instance-id forces cloud-init to re-run) ------

echo "[*] Regenerating cloud-init seed..."
PUB_KEY=$(cat "$SSH_KEY.pub")

cat > "$HARNESS_DIR/user-data" <<USERDATA
#cloud-config
password: ubuntu
chpasswd: { expire: False }
ssh_pwauth: True
users:
  - name: ubuntu
    sudo: ALL=(ALL) NOPASSWD:ALL
    groups: sudo
    shell: /bin/bash
    ssh_authorized_keys:
      - $PUB_KEY
runcmd:
  - mkdir -p /mnt/angband
  - |
    if ! mountpoint -q /mnt/angband 2>/dev/null; then
      mount -t 9p -o trans=virtio,version=9p2000.L host0 /mnt/angband || true
    fi
  - echo 'host0 /mnt/angband 9p trans=virtio,version=9p2000.L,nofail 0 0' >> /etc/fstab
  - echo 'Angband cloud-init done' > /var/log/angband-init.log
USERDATA

cat > "$HARNESS_DIR/meta-data" <<METADATA
instance-id: angband-$(date +%s)
local-hostname: angband
METADATA

cloud-localds "$HARNESS_DIR/seed.img" "$HARNESS_DIR/user-data" "$HARNESS_DIR/meta-data"
rm -f "$HARNESS_DIR/user-data" "$HARNESS_DIR/meta-data"

# ------ Clean stale files ------

rm -f "$HARNESS_DIR/qemu.pid" "$HARNESS_DIR/qemu_wrapper.pid" "$HARNESS_DIR/qemu.log"

echo ""
echo "[+] Reset complete.  Fresh overlay ready."
echo "    Run 'bash harness/launch.sh' to boot the VM."
