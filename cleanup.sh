#!/bin/bash
# ---------------------------------------------------------------
# cleanup.sh -- Remove all generated Angband runtime state
#
# Usage:
#   bash cleanup.sh             Remove runtime state (keeps base image and venv)
#   bash cleanup.sh --all       Also remove cached Ubuntu base image (~600 MB)
#   bash cleanup.sh --nuke      Remove everything including venv
#   bash cleanup.sh -h|--help   Show help
# ---------------------------------------------------------------
set -euo pipefail

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$SCRIPT_DIR"

RUNTIME_ROOT="mordor_run"
CURRENT_DIR="$RUNTIME_ROOT/current"
HARNESS_DIR="$RUNTIME_ROOT/harness"
CACHE_DIR="$RUNTIME_ROOT/cache"
SSH_DIR="$RUNTIME_ROOT/ssh"

ARG="${1:-}"

if [ "$ARG" = "-h" ] || [ "$ARG" = "--help" ]; then
    cat <<'EOF'
Usage: bash cleanup.sh [OPTION]

Remove generated Angband runtime state and build artifacts.

Options:
  (none)      Remove runtime state: exploit output, QEMU overlay/seed,
              SSH keys, kernel module build artifacts, Python caches.
              Keeps: cached Ubuntu base image, Python venv.

  --all       Also remove the cached Ubuntu base image (~600 MB).
              Keeps: Python venv.

  --nuke      Remove everything: runtime, cache, venv, all build artifacts.

  -h, --help  Show this help message.
EOF
    exit 0
fi

echo "[Angband] Cleaning up..."

# ---- 1. Stop QEMU if running ----

if [ -f "$HARNESS_DIR/qemu.pid" ]; then
    PID=$(cat "$HARNESS_DIR/qemu.pid" 2>/dev/null || true)
    if [ -n "$PID" ] && kill -0 "$PID" 2>/dev/null; then
        echo "[*] Stopping QEMU VM (PID $PID)..."
        bash harness/stop.sh 2>/dev/null || true
    fi
fi

# ---- 2. Remove generated exploit output ----

if [ -d "$CURRENT_DIR" ]; then
    echo "[*] Removing mordor_run/current/ (exploit output, logs)..."
    rm -rf "$CURRENT_DIR"
fi

# ---- 3. Remove QEMU harness state (overlay, seed, pid files, logs) ----

if [ -d "$HARNESS_DIR" ]; then
    echo "[*] Removing mordor_run/harness/ (VM overlay, seed, logs)..."
    rm -rf "$HARNESS_DIR"
fi

# ---- 4. Remove SSH keys ----

if [ -d "$SSH_DIR" ]; then
    echo "[*] Removing mordor_run/ssh/ (SSH key pair)..."
    rm -rf "$SSH_DIR"
fi

# ---- 5. Clean kernel module build artifacts ----

if [ -f "module/vuln_drill/Makefile" ]; then
    echo "[*] Cleaning kernel module build artifacts..."
    # Use make clean if kernel headers are available, otherwise manual removal
    if make -C module/vuln_drill clean 2>/dev/null; then
        true
    else
        rm -f module/vuln_drill/*.o \
              module/vuln_drill/*.ko \
              module/vuln_drill/*.mod \
              module/vuln_drill/*.mod.c \
              module/vuln_drill/*.mod.o \
              module/vuln_drill/Module.symvers \
              module/vuln_drill/modules.order \
              module/vuln_drill/.*.cmd \
              2>/dev/null || true
        rm -rf module/vuln_drill/.tmp_versions 2>/dev/null || true
    fi
fi

# ---- 6. Clean Python build artifacts (not the venv) ----

echo "[*] Removing Python build caches..."
rm -rf angband.egg-info/ build/ dist/
find . -path ./venv -prune -o -type d -name "__pycache__" -print -exec rm -rf {} + 2>/dev/null || true
find . -path ./venv -prune -o -type f -name "*.pyc" -print -delete 2>/dev/null || true

# ---- 7. Remove legacy files (from older project layouts) ----

rm -f exploit exploit.c exploit.yaml exploit_run.log dmesg_tail.log 2>/dev/null || true
rm -f .ssh_key .ssh_key.pub 2>/dev/null || true

# ---- 8. Deep clean: remove cached base image ----

if [ "$ARG" = "--all" ] || [ "$ARG" = "--nuke" ]; then
    if [ -d "$CACHE_DIR" ]; then
        echo "[*] Removing mordor_run/cache/ (Ubuntu base image)..."
        rm -rf "$CACHE_DIR"
    fi
fi

# ---- 9. Nuke: remove venv too ----

if [ "$ARG" = "--nuke" ]; then
    if [ -d "venv" ]; then
        echo "[*] Removing Python virtual environment..."
        rm -rf venv/
    fi
fi

# ---- 10. Remove empty mordor_run if nothing left ----

if [ -d "$RUNTIME_ROOT" ]; then
    # Remove if only empty subdirectories remain
    if [ -z "$(find "$RUNTIME_ROOT" -type f 2>/dev/null)" ]; then
        rm -rf "$RUNTIME_ROOT"
    fi
fi

echo "[+] Cleanup complete."
echo ""

# Show what remains
if [ -d "$CACHE_DIR" ]; then
    SIZE=$(du -sh "$CACHE_DIR" 2>/dev/null | cut -f1)
    echo "    Kept: $CACHE_DIR ($SIZE) -- use --all to remove"
fi
if [ -d "venv" ]; then
    echo "    Kept: venv/ -- use --nuke to remove"
fi
