#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${YELLOW}[*] sidewinder cleanup${NC}"

# 1. Kill any lingering rowhammer/side-channel probe processes
echo -e "${YELLOW}[*] Terminating probe processes...${NC}"
PROCS=$(pgrep -f "sidewinder" 2>/dev/null || true)
if [ -n "$PROCS" ]; then
    for pid in $PROCS; do
        kill -9 "$pid" 2>/dev/null || true
        echo -e "  ${GREEN}Killed PID $pid${NC}"
    done
else
    echo -e "  ${GREEN}No running sidewinder processes${NC}"
fi

# 2. Release any huge pages allocated by the tool
echo -e "${YELLOW}[*] Releasing huge pages...${NC}"
if [ -f /proc/sys/vm/nr_hugepages ]; then
    ORIG=$(cat /proc/sys/vm/nr_hugepages 2>/dev/null || echo "0")
    if [ "$ORIG" != "0" ]; then
        echo 0 > /proc/sys/vm/nr_hugepages 2>/dev/null || {
            echo -e "  ${YELLOW}Could not release huge pages (needs root)${NC}"
        }
        echo -e "  ${GREEN}Released $ORIG huge pages${NC}"
    else
        echo -e "  ${GREEN}No huge pages allocated${NC}"
    fi
else
    echo -e "  ${YELLOW}No huge pages configured${NC}"
fi

# 3. Unmount any leftover hugetlbfs
if mountpoint -q /mnt/huge 2>/dev/null; then
    echo -e "${YELLOW}[*] Unmounting /mnt/huge...${NC}"
    umount /mnt/huge 2>/dev/null || {
        echo -e "  ${YELLOW}Could not unmount /mnt/huge (needs root)${NC}"
    }
    echo -e "  ${GREEN}Unmounted${NC}"
fi

# 4. Clear temp files
echo -e "${YELLOW}[*] Cleaning temporary files...${NC}"
rm -rf /tmp/sidewinder_* 2>/dev/null || true
rm -f /tmp/rowhammer_* /tmp/sidechannel_* 2>/dev/null || true
echo -e "  ${GREEN}Temporary files removed${NC}"

# 5. Restore CPU affinity/frequency if changed (best-effort)
if command -v cpupower &>/dev/null; then
    echo -e "${YELLOW}[*] Restoring CPU governor to ondemand...${NC}"
    cpupower frequency-set -g ondemand > /dev/null 2>&1 || {
        echo -e "  ${YELLOW}Could not set governor (needs root)${NC}"
    }
    echo -e "  ${GREEN}Restored${NC}"
fi

# 6. Clean build artifacts in this project
echo -e "${YELLOW}[*] Cleaning build artifacts...${NC}"
rm -rf "$SCRIPT_DIR/build" "$SCRIPT_DIR/dist" "$SCRIPT_DIR/__pycache__"
rm -rf "$SCRIPT_DIR/c_primitives/build"
rm -f "$SCRIPT_DIR"/c_primitives/*.o
find "$SCRIPT_DIR" -name "*.pyc" -delete 2>/dev/null || true
find "$SCRIPT_DIR" -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true
echo -e "  ${GREEN}Build artifacts removed${NC}"

# 7. Restore CPU affinity of current shell
if command -v taskset &>/dev/null; then
    taskset -p 0xffffffff $$ > /dev/null 2>&1 || true
fi

echo -e "${GREEN}[+] Cleanup complete${NC}"
