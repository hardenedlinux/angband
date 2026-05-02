#!/bin/bash
set -euo pipefail

SERIAL_LOG="${SCRIPT_DIR:-/home/john/angband/mordor_run/harness}/harness/serial.log"
echo "[Angband] Reading kernel logs from serial..."
echo "[*] File: $SERIAL_LOG"
echo ""
tail -n 50 "$SERIAL_LOG" 2>/dev/null || echo "[!] Serial log not found. Is VM running?"