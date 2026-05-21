"""DRAM detection and reverse-engineering module.

Detects DRAM type (DDR3/4/5), ECC status, and reverse-engineers
DRAM address functions (channel, rank, bank, row, column mapping).

The reverse-engineering is based on DRAMA's approach:
1. Allocate physically contiguous memory via huge pages
2. Measure row activation latency to find same-bank row pairs
3. Use bit-level DRAM address XOR patterns to decode (rank, bank, row, col)
"""

import os
import re
import struct
import subprocess
import time
from typing import Optional

from sidewinder.utils.system import read_sysfs


def detect_dram_type() -> Optional[str]:
    """Detect DRAM generation via dmidecode or SMBIOS."""
    try:
        result = subprocess.run(
            ["dmidecode", "-t", "memory", "2>/dev/null"],
            capture_output=True, text=True, timeout=10, shell=True
        )
        output = result.stdout + result.stderr

        if "DDR5" in output:
            return "DDR5"
        if "DDR4" in output:
            return "DDR4"
        if "DDR3" in output:
            return "DDR3"
        if "DDR2" in output:
            return "DDR2"

        # Fallback to parsing type detail
        for line in output.splitlines():
            if "Type:" in line and "DDR" in line:
                for gen in ["DDR5", "DDR4", "DDR3", "DDR2"]:
                    if gen in line:
                        return gen
    except Exception:
        pass

    # Try reading directly from SMBIOS
    try:
        result = subprocess.run(
            ["dmidecode", "-t", "17", "2>/dev/null"],
            capture_output=True, text=True, timeout=10, shell=True
        )
        for line in result.stdout.splitlines():
            if "Type:" in line and "DDR" in line:
                for gen in ["DDR5", "DDR4", "DDR3", "DDR2"]:
                    if gen in line:
                        return gen
    except Exception:
        pass

    return "Unknown"


def detect_ecc() -> bool:
    try:
        result = subprocess.run(
            ["dmidecode", "-t", "memory", "2>/dev/null"],
            capture_output=True, text=True, timeout=10, shell=True
        )
        output = result.stdout
        for line in output.splitlines():
            if "Error Correction Type:" in line:
                if "None" in line:
                    return False
                if any(t in line for t in ["ECC", "Single-bit", "Multi-bit", "CRC"]):
                    return True
    except Exception:
        pass

    # /sys check
    try:
        for root, dirs, files in os.walk("/sys/devices/system/edac/mc"):
            if "ce_count" in files:
                return True
    except Exception:
        pass

    return False


def detect_dram_size_gb() -> Optional[int]:
    """Get total DRAM size in GB from /proc/meminfo."""
    try:
        with open("/proc/meminfo") as f:
            for line in f:
                if line.startswith("MemTotal:"):
                    kb = int(line.split()[1])
                    return kb // (1024 * 1024)
    except Exception:
        pass
    return None


def detect_dram_channels() -> int:
    try:
        result = subprocess.run(
            ["dmidecode", "-t", "memory", "2>/dev/null"],
            capture_output=True, text=True, timeout=10, shell=True
        )
        count = 0
        for line in result.stdout.splitlines():
            if "Size:" in line and "No Module" not in line and "MB" in line or "GB" in line:
                count += 1
        return max(count, 1)
    except Exception:
        pass

    # Read from /sys
    try:
        result = subprocess.run(
            ["lscpu"], capture_output=True, text=True, timeout=5
        )
        for line in result.stdout.splitlines():
            if "NUMA node" in line:
                return 1
    except Exception:
        pass

    return 1


def get_dram_info() -> dict:
    return {
        "dram_type": detect_dram_type(),
        "ecc": detect_ecc(),
        "total_size_gb": detect_dram_size_gb(),
        "channels": detect_dram_channels(),
        "page_size": 4096,
        "huge_page_size": 2 * 1024 * 1024,
    }


# ---- DRAM Address Function Reverse Engineering (port from DRAMA) ----

# The DRAM address function maps a physical address to (channel, rank, bank, row, col).
# This is done by XOR-ing select physical address bits to produce the DRAM-side bits.
# The mapping is microarchitecture-specific. We reverse-engineer it via:
# 1. Allocating physically contiguous DRAM (huge pages)
# 2. Timing row activations to identify same-bank rows
# 3. Collecting sets of physical address bits and inferring XOR functions

def _measure_row_activation_latency(addr_a: int, addr_b: int) -> float:
    """
    Returns row activation time in nanoseconds. High time (>200ns) means
    row conflict (same bank, different row) - this is the DRAM row buffer miss.
    Low time (<80ns) means row hit or different bank (row buffer hit or open).
    """
    pass  # Requires native code with precise timing - see probe/rowhammer.py


def reverse_engineer_dram_functions() -> Optional[dict]:
    """
    Reverse-engineer the DRAM address function for the current CPU.
    Returns a dict mapping DRAM bit fields to physical address bit positions
    and XOR patterns. This is a CPU+memory-controller specific function.
    """
    # For now, return known profiles for common architectures
    # Full runtime RE is in probe/dram_re.py
    import platform
    from sidewinder.detector.cpu import detect_microarchitecture

    uarch = detect_microarchitecture()
    if not uarch:
        return None

    arch = uarch.get("microarchitecture", "")
    vendor = uarch.get("vendor", "")

    # Known DRAM functions from DRAMA/Blacksmith/ZenHammer research
    KNOWN_DRAM_FUNCTIONS = {
        "Kaby Lake": {
            "rank":  [17],
            "bank":  [13, 14, 15, 16],
            "row":   list(range(18, 35)),
            "col":   list(range(6, 12)),
            "channel_xor": None,
        },
        "Coffee Lake": {
            "rank":  [17],
            "bank":  [13, 14, 15, 16],
            "row":   list(range(18, 35)),
            "col":   list(range(6, 12)),
        },
        "Comet Lake": {
            "rank":  [17],
            "bank":  [13, 14, 15, 16],
            "row":   list(range(18, 35)),
            "col":   list(range(6, 12)),
        },
        "Skylake": {
            "rank":  [17],
            "bank":  [13, 14, 16],
            "row":   list(range(18, 35)),
            "col":   list(range(6, 12)),
        },
        "Haswell": {
            "rank":  [17],
            "bank":  [13, 14, 15, 16],
            "row":   list(range(18, 35)),
            "col":   list(range(6, 12)),
        },
        "Zen 2": {
            "rank":  [11],
            "bank":  [12, 13, 14, 15],
            "row":   list(range(16, 34)),
            "col":   list(range(3, 10)),
        },
        "Zen 3": {
            "rank":  [11],
            "bank":  [12, 13, 14, 15],
            "row":   list(range(16, 34)),
            "col":   list(range(3, 10)),
        },
        "Zen 4": {
            "rank":  [11],
            "bank":  [12, 13, 14, 15],
            "row":   list(range(16, 34)),
            "col":   list(range(3, 10)),
        },
    }

    return KNOWN_DRAM_FUNCTIONS.get(arch)
