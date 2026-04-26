#!/bin/bash

# Configuration
IMAGE="ubuntu-24.04-server-cloudimg-amd64.img"
IMAGE_URL="https://cloud-images.ubuntu.com/releases/24.04/release/$IMAGE"

echo "[Angband] Environment Setup"

if [ ! -f "$IMAGE" ]; then
    echo "[*] Downloading Ubuntu cloud image..."
    wget -q --show-progress "$IMAGE_URL"
    qemu-img resize "$IMAGE" +5G
fi

# Create cloud-init seed image with password auth and authorized ssh keys
if [ ! -f "seed.img" ]; then
    echo "[*] Creating cloud-init seed image..."
    
    # Generate SSH key if not exists to allow automatic login without password
    if [ ! -f "../.ssh_key" ]; then
        ssh-keygen -t ed25519 -f "../.ssh_key" -N "" -q
    fi
    PUB_KEY=$(cat ../.ssh_key.pub)

    cat > user-data <<EOF
#cloud-config
password: ubuntu
chpasswd: { expire: False }
ssh_pwauth: True
users:
  - name: ubuntu
    sudo: ALL=(ALL) NOPASSWD:ALL
    groups: sudo
    ssh_authorized_keys:
      - $PUB_KEY
runcmd:
  - mkdir -p /mnt/angband
  - mount -t 9p -o trans=virtio,version=9p2000.L host0 /mnt/angband
  - chmod 777 /mnt/angband
  - echo 'Done with cloud-init' > /var/log/angband-init.log
EOF
    cat > meta-data <<EOF
instance-id: angband-test
local-hostname: angband
EOF
    cloud-localds seed.img user-data meta-data
    rm user-data meta-data
fi

echo "[+] Setup complete. You can now start the VM using ./launch.sh"