#!/bin/bash

IMAGE="ubuntu-24.04-server-cloudimg-amd64.img"

if [ ! -f "$IMAGE" ] || [ ! -f "seed.img" ]; then
    echo "[!] Environment not set up. Please run ./setup.sh first."
    exit 1
fi

echo "[*] Launching QEMU in background..."
nohup qemu-system-x86_64 \
    -m 4G \
    -smp 2 \
    -hda "$IMAGE" \
    -drive if=virtio,format=raw,file=seed.img \
    -net user,hostfwd=tcp::2222-:22 -net nic \
    -display none \
    -s \
    -virtfs local,path=../,mount_tag=host0,security_model=passthrough,id=host0 \
    -serial telnet:localhost:4444,server,nowait \
    -pidfile qemu.pid \
    "$@" > qemu.log 2>&1 &

echo $! > qemu_wrapper.pid
echo "[+] QEMU started. Use 'cat qemu.log' to monitor boot process."
