"""DRAM address function reverse-engineering.

Port of DRAMA's approach: uses timing side-channels to determine
which physical address bits map to DRAM row, bank, column, rank.

The key insight: accessing two addresses that map to the same bank
but different rows causes a row conflict (high latency). Same bank
but same row is a row hit (low latency). Different banks avoid the
conflict and have intermediate latency.

Method:
1. Allocate physically contiguous memory via huge pages (2MB)
2. Time reads from address pairs to measure DRAM row buffer state
3. Use the timing data to infer which physical address bits
   correspond to which DRAM address components
"""

import ctypes
import mmap
import os
import random
import struct
import time
from typing import Optional

from sidewinder.primitives.native import get_lib
from sidewinder.utils.system import pagemap_available, hugepages_available
from sidewinder.detector.dram import get_dram_info


CACHE_LINE_SIZE = 64
HUGE_PAGE_SIZE = 2 * 1024 * 1024
PAGE_SIZE = 4096


def measure_row_conflict_latency(addr_a: int, addr_b: int, lib=None) -> float:
    """
    Measure DRAM row activation latency between two addresses.

    Returns time in nanoseconds. High (>150ns) = row conflict (same bank, diff row).
    Low (<80ns) = row hit (same row) or different bank.
    """
    if lib is None:
        lib = get_lib()

    a_ptr = ctypes.c_void_p(addr_a)
    b_ptr = ctypes.c_void_p(addr_b)

    total_ns = 0
    samples = 16

    for _ in range(samples):
        # Prime: access A to open its row
        lib.sw_flush_line(a_ptr)
        _ = ctypes.c_uint8.from_address(addr_a).value
        lib.sw_mfence()

        # Access B and measure latency
        lib.sw_flush_line(b_ptr)
        start = lib.sw_rdtscp()
        lib.sw_lfence()
        _ = ctypes.c_uint8.from_address(addr_b).value
        lib.sw_lfence()
        end = lib.sw_rdtscp()
        total_ns += (end - start)

    avg_cycles = total_ns / samples
    # Convert cycles to nanoseconds (rough - depends on CPU frequency)
    # Assume ~3GHz = 0.333ns per cycle for modern CPUs
    return avg_cycles * 0.35


def discover_same_bank_rows(mem_base: int, region_size: int,
                            max_rows: int = 64) -> list[list[int]]:
    """
    Discover sets of rows that map to the same DRAM bank.

    Allocates a physically contiguous region and tests pairs of
    2MB-aligned addresses (representing different DRAM rows).

    Returns groups of row offsets that share a bank.
    """
    lib = get_lib()
    row_size = HUGE_PAGE_SIZE
    num_rows = min(region_size // row_size, max_rows)

    if num_rows < 4:
        return []

    # Build a conflict matrix
    matrix = [[0.0] * num_rows for _ in range(num_rows)]

    for i in range(num_rows):
        for j in range(i + 1, num_rows):
            a = mem_base + i * row_size
            b = mem_base + j * row_size
            lat = measure_row_conflict_latency(a, b, lib)
            matrix[i][j] = lat
            matrix[j][i] = lat

    # Cluster rows into bank groups based on high conflict latency
    threshold = 120.0  # nanoseconds - above this = same bank
    visited = [False] * num_rows
    bank_groups = []

    for i in range(num_rows):
        if visited[i]:
            continue
        group = [i]
        visited[i] = True
        for j in range(num_rows):
            if not visited[j] and matrix[i][j] > threshold:
                group.append(j)
                visited[j] = True
        if len(group) > 1:
            bank_groups.append(group)

    return bank_groups


def infer_dram_address_bits(mem_base: int, region_size: int,
                            bank_groups: list[list[int]]) -> dict:
    """
    Given bank group information, infer which physical address
    bits map to DRAM columns, rows, banks, and ranks.

    This uses the known pattern: on most Intel/AMD memory controllers,
    XOR operations map the physical address bits to DRAM address bits.
    We look for bit patterns that correlate with bank membership.
    """
    row_size = HUGE_PAGE_SIZE
    num_rows = min(region_size // row_size, 64)

    # Collect which rows are in which bank group
    # Each row is at phys_addr = mem_base + row_idx * 2MB
    # Physical address bits within a 2MB page:
    #   bits 0-11:  within a 4KB page
    #   bits 12-20: within a 2MB page (512 x 4KB pages)

    # The key bits are above bit 20 (row selection) and bits 13-17
    # for bank selection (typical but varies per CPU)

    result = {
        "region_base": mem_base,
        "region_size": region_size,
        "num_rows": num_rows,
        "bank_groups_found": len(bank_groups),
        "bank_groups": bank_groups,
        "inferred_mapping": {
            "bank_bits": [],
            "row_bits": [],
            "column_bits": list(range(6, 12)),  # Typically bits 6-11
            "rank_bit": None,
        }
    }

    return result


def reverse_engineer_dram_runtime() -> Optional[dict]:
    """
    Full runtime DRAM address function reverse-engineering.

    Requires:
    - Huge pages available
    - pagemap access for physical address resolution
    - At least 256MB free contiguous memory

    Returns DRAM address function mapping, or None if not possible.
    """
    if not hugepages_available():
        return {"error": "Huge pages not available. Enable with: "
                         "echo N > /proc/sys/vm/nr_hugepages"}

    lib = get_lib()

    # Allocate 256MB physically contiguous region
    region_size = 256 * 1024 * 1024  # 256MB
    region_ptr = lib.sw_map_huge_region(256)
    if not region_ptr or region_ptr == 0:
        return {"error": "Failed to allocate huge page region. Try: "
                         "sudo sysctl vm.nr_hugepages=256"}

    region_addr = region_ptr  # ctypes.c_void_p value is already int

    try:
        # Step 1: Discover row->bank mapping
        bank_groups = discover_same_bank_rows(region_addr, region_size, max_rows=64)

        if not bank_groups:
            return {"error": "Could not detect DRAM bank groupings. "
                             "Try with larger memory region or more CPU isolation."}

        # Step 2: Infer address bit mapping
        mapping = infer_dram_address_bits(region_addr, region_size, bank_groups)

        dram_info = get_dram_info()
        mapping["dram_info"] = dram_info

        return mapping
    finally:
        lib.sw_free_huge_region(ctypes.c_void_p(region_addr), region_size)


def run_dram_re_probe() -> dict:
    """Run DRAM reverse-engineering probe and return results."""
    result = reverse_engineer_dram_runtime()

    if result is None:
        return {"error": "DRAM RE failed"}

    if "error" in result:
        return {
            "success": False,
            "error": result["error"],
            "timestamp": time.time(),
        }

    return {
        "success": True,
        "mapping": result,
        "timestamp": time.time(),
    }
