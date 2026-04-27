#!/bin/bash
# ---------------------------------------------------------------
# harness/stop.sh -- Stop the QEMU test VM
# ---------------------------------------------------------------
set -euo pipefail

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
HARNESS_DIR="$REPO_ROOT/mordor_run/harness"

echo "[Angband] Stopping QEMU VM..."

stopped=0

# Kill the wrapper (nohup shell) first
if [ -f "$HARNESS_DIR/qemu_wrapper.pid" ]; then
    WRAPPER_PID=$(cat "$HARNESS_DIR/qemu_wrapper.pid")
    if kill -0 "$WRAPPER_PID" 2>/dev/null; then
        kill "$WRAPPER_PID" 2>/dev/null || true
    fi
    rm -f "$HARNESS_DIR/qemu_wrapper.pid"
fi

# Then kill the QEMU process
if [ -f "$HARNESS_DIR/qemu.pid" ]; then
    QEMU_PID=$(cat "$HARNESS_DIR/qemu.pid")
    if kill -0 "$QEMU_PID" 2>/dev/null; then
        echo "[*] Terminating QEMU (PID $QEMU_PID)..."
        kill "$QEMU_PID" 2>/dev/null || true
        # Wait up to 5 seconds for graceful shutdown
        for i in $(seq 1 10); do
            if ! kill -0 "$QEMU_PID" 2>/dev/null; then
                break
            fi
            sleep 0.5
        done
        # Force kill if still running
        if kill -0 "$QEMU_PID" 2>/dev/null; then
            echo "[*] Force-killing QEMU..."
            kill -9 "$QEMU_PID" 2>/dev/null || true
        fi
        stopped=1
    fi
    rm -f "$HARNESS_DIR/qemu.pid"
fi

if [ "$stopped" -eq 1 ]; then
    echo "[+] QEMU stopped."
else
    echo "[-] No running QEMU instance found."
fi
