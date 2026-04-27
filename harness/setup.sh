#!/bin/bash
# ---------------------------------------------------------------
# harness/setup.sh -- One-time preparation of the QEMU test target
#
# This script:
#   1. Downloads the Ubuntu 24.04 cloud image (cached, never modified)
#   2. Generates an SSH key pair for guest access
#   3. Creates a cloud-init seed image that provisions the guest
#   4. Creates a qcow2 overlay snapshot backed by the base image
#
# The base image in cache/ is NEVER written to.  All guest writes
# go into the overlay in harness/.  To reset the VM to a fresh
# state, run harness/reset.sh (instant, no re-download needed).
# ---------------------------------------------------------------
set -euo pipefail

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
RUNTIME_ROOT="$REPO_ROOT/mordor_run"
CACHE_DIR="$RUNTIME_ROOT/cache"
HARNESS_DIR="$RUNTIME_ROOT/harness"
SSH_DIR="$RUNTIME_ROOT/ssh"
BASE_IMAGE_NAME="ubuntu-24.04-server-cloudimg-amd64.img"
BASE_IMAGE="$CACHE_DIR/$BASE_IMAGE_NAME"
IMAGE_URL="https://cloud-images.ubuntu.com/releases/24.04/release/$BASE_IMAGE_NAME"
OVERLAY_IMAGE="$HARNESS_DIR/disk.qcow2"
SSH_KEY="$SSH_DIR/id_ed25519"

echo "============================================"
echo "  Angband QEMU Target Preparation"
echo "============================================"
echo ""

# ------ Step 0: Check host dependencies ------

echo "[Step 0] Checking host dependencies..."

MISSING=""
command -v qemu-system-x86_64 >/dev/null 2>&1 || MISSING="$MISSING qemu-system-x86"
command -v qemu-img           >/dev/null 2>&1 || MISSING="$MISSING qemu-system-x86"
command -v cloud-localds      >/dev/null 2>&1 || MISSING="$MISSING cloud-image-utils"
command -v ssh-keygen         >/dev/null 2>&1 || MISSING="$MISSING openssh-client"

if [ -n "$MISSING" ]; then
    echo "[!] Missing packages:$MISSING"
    echo "    Install them with:  sudo apt-get install -y$MISSING"
    exit 1
fi
echo "[+] All dependencies present."
echo ""

# ------ Step 1: Create directory structure ------

echo "[Step 1] Creating directory structure..."
mkdir -p "$CACHE_DIR" "$HARNESS_DIR" "$SSH_DIR"
echo "[+] mordor_run/cache/    -- base image storage (never modified)"
echo "[+] mordor_run/harness/  -- VM overlay, seed, logs, PID files"
echo "[+] mordor_run/ssh/      -- SSH key pair for guest access"
echo ""

# ------ Step 2: Download base image (one-time, cached) ------

echo "[Step 2] Preparing base cloud image..."
if [ -f "$BASE_IMAGE" ]; then
    # Validate existing image
    if qemu-img info "$BASE_IMAGE" >/dev/null 2>&1; then
        echo "[+] Base image already cached: $BASE_IMAGE"
        echo "    ($(du -h "$BASE_IMAGE" | cut -f1))"
    else
        echo "[!] Cached image is corrupted.  Re-downloading..."
        rm -f "$BASE_IMAGE"
    fi
fi

if [ ! -f "$BASE_IMAGE" ]; then
    echo "[*] Downloading Ubuntu 24.04 cloud image..."
    echo "    URL: $IMAGE_URL"
    echo "    This is a one-time download (~600 MB).  Future resets are instant."
    echo ""
    wget -q --show-progress -c "$IMAGE_URL" -O "$BASE_IMAGE.tmp"
    mv "$BASE_IMAGE.tmp" "$BASE_IMAGE"
    echo "[+] Download complete."
fi
echo ""

# ------ Step 3: Generate SSH keys ------

echo "[Step 3] Generating SSH key pair..."
if [ -f "$SSH_KEY" ]; then
    echo "[+] SSH key already exists: $SSH_KEY"
else
    ssh-keygen -t ed25519 -f "$SSH_KEY" -N "" -q
    echo "[+] Generated: $SSH_KEY"
fi
echo "    Public key: $(cat "$SSH_KEY.pub")"
echo ""

# ------ Step 4: Create cloud-init seed image ------

echo "[Step 4] Creating cloud-init seed image..."
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
echo "[+] Seed image created: $HARNESS_DIR/seed.img"
echo "    Guest user:     ubuntu"
echo "    Guest password:  ubuntu  (SSH key auth is preferred)"
echo ""

# ------ Step 5: Create qcow2 overlay (snapshot) ------

echo "[Step 5] Creating qcow2 overlay snapshot..."
if [ -f "$OVERLAY_IMAGE" ]; then
    echo "[*] Removing old overlay..."
    rm -f "$OVERLAY_IMAGE"
fi

qemu-img create -f qcow2 -b "$BASE_IMAGE" -F qcow2 "$OVERLAY_IMAGE" 10G >/dev/null 2>&1
echo "[+] Overlay created: $OVERLAY_IMAGE"
echo "    Backed by:  $BASE_IMAGE  (read-only)"
echo "    Guest disk:  10 GB total"
echo ""

# ------ Done ------

echo "============================================"
echo "  Setup complete!"
echo "============================================"
echo ""
echo "  Next steps:"
echo "    1. Launch the VM:    bash harness/launch.sh"
echo "    2. Wait ~60s for first boot (cloud-init provisioning)"
echo "    3. SSH into guest:   ssh -i mordor_run/ssh/id_ed25519 -p 2222 ubuntu@localhost"
echo "    4. Run the demo:     bash run_and_verify.sh"
echo ""
echo "  To reset the VM to a clean state (instant, no re-download):"
echo "    bash harness/reset.sh"
echo ""
