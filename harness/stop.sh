#!/bin/bash

echo "[Angband] Stopping QEMU Harness..."

if [ -f "qemu_wrapper.pid" ]; then
    WRAPPER_PID=$(cat qemu_wrapper.pid)
    echo "[*] Killing wrapper process $WRAPPER_PID..."
    kill -9 $WRAPPER_PID 2>/dev/null
    rm qemu_wrapper.pid
fi

if [ -f "qemu.pid" ]; then
    QEMU_PID=$(cat qemu.pid)
    echo "[*] Terminating QEMU VM (PID: $QEMU_PID)..."
    kill $QEMU_PID 2>/dev/null
    
    # Wait for graceful shutdown
    sleep 2
    if kill -0 $QEMU_PID 2>/dev/null; then
        echo "[!] QEMU did not terminate gracefully. Forcing kill..."
        kill -9 $QEMU_PID 2>/dev/null
    fi
    
    rm qemu.pid
    echo "[+] QEMU stopped."
else
    # Fallback if PID file is missing
    QEMU_PIDS=$(pgrep -f "qemu-system-x86_64.*-pidfile qemu.pid")
    if [ ! -z "$QEMU_PIDS" ]; then
        echo "[*] Found lingering QEMU processes. Killing..."
        kill -9 $QEMU_PIDS 2>/dev/null
        echo "[+] Lingering QEMU instances stopped."
    else
        echo "[-] No QEMU instance found running."
    fi
fi
