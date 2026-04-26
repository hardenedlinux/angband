#!/bin/bash

echo "[Angband] Cleaning up project artifacts..."

# 1. Stop QEMU if running
if [ -f "harness/stop.sh" ]; then
    (cd harness && ./stop.sh)
fi

# 2. Clean kernel module
if [ -f "module/vuln_drill/Makefile" ]; then
    echo "[*] Cleaning kernel module..."
    (cd module/vuln_drill && make clean 2>/dev/null || true)
fi

# 3. Remove generated exploit files and logs
echo "[*] Removing generated exploit files and logs..."
rm -f exploit exploit.c exploit.yaml exploit_run.log dmesg_tail.log

# 4. Remove QEMU harness state
# Note: We keep the base Ubuntu image by default so you don't have to re-download it.
echo "[*] Removing QEMU state and SSH keys..."
rm -f harness/seed.img harness/qemu.log harness/*.pid harness/qemu_wrapper.pid
rm -f .ssh_key .ssh_key.pub

# 5. Clean Python artifacts
echo "[*] Removing Python caches and virtual environment..."
rm -rf venv/ angband.egg-info/ build/
find . -type d -name "__pycache__" -exec rm -rf {} +
find . -type f -name "*.pyc" -delete

# 6. Deep clean option
if [ "$1" == "--all" ] || [ "$1" == "all" ]; then
    echo "[*] Deep clean: Removing downloaded Ubuntu base images..."
    rm -f harness/*.img
fi

echo "[+] Cleanup complete!"