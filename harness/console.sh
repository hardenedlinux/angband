#!/bin/bash
set -euo pipefail

echo "[Angband] QEMU Console Access"
echo ""
echo "  Kernel log (tail -f):  tail -f mordor_run/harness/serial.log"
echo "  QEMU Monitor:          telnet localhost 4445"
echo "  GDB:                   localhost:1234"
