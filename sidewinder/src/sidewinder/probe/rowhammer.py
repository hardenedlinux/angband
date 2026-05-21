"""Rowhammer fuzzer using Blacksmith-style frequency-based hammer patterns.

Performs non-uniform DRAM hammering with parameterized frequency/phase/amplitude
patterns to bypass TRR (Target Row Refresh) on DDR4 and trigger bit flips.

Architecture:
1. Allocate physically contiguous DRAM via huge pages (2MB pages)
2. Generate frequency-based hammer patterns (Blacksmith model)
3. Hammer aggressor rows with non-uniform timing
4. Check victim rows for bit flips
5. Characterize flips (address, bit position, from/to values)
"""

import ctypes
import mmap
import os
import signal
import time
from dataclasses import dataclass, field
from typing import Optional

from sidewinder.primitives.native import get_lib
from sidewinder.detector.dram import get_dram_info, reverse_engineer_dram_functions
from sidewinder.probe.dram_re import discover_same_bank_rows


CACHE_LINE_SIZE = 64
HUGE_PAGE_SIZE = 2 * 1024 * 1024
PAGE_SIZE = 4096


@dataclass
class FlipRecord:
    address: int
    bit: int
    from_byte: int
    to_byte: int
    phys_addr: int = 0


@dataclass
class RowhammerResult:
    flips: list[FlipRecord] = field(default_factory=list)
    total_activations: int = 0
    duration_sec: float = 0.0
    patterns_tried: int = 0
    rows_hammered: int = 0
    dram_type: str = "Unknown"
    success: bool = False
    error: str = ""


def _allocate_hammer_region(mb: int = 256):
    """Allocate physically contiguous region for rowhammer testing."""
    lib = get_lib()
    size = mb * 1024 * 1024
    ptr = lib.sw_map_huge_region(mb)
    if not ptr or ptr == 0:
        raise RuntimeError(
            f"Failed to allocate {mb}MB huge pages. "
            "Try: sudo sysctl vm.nr_hugepages={mb // 2}"
        )
    return ptr, size


def _generate_blacksmith_patterns(count: int = 32) -> list:
    """Generate Blacksmith-style frequency-based hammer patterns.

    Each pattern is parameterized by (frequency, phase, amplitude):
    - frequency: oscillation speed of inter-activation delay (0.1 - 2.0)
    - phase: offset within oscillation cycle (0 - 2*PI)
    - amplitude: magnitude of delay variation (20 - 100ns)
    """
    import math
    patterns = []
    for i in range(count):
        freq = 0.1 + (i / count) * 2.0
        phase = (i * math.pi) / count
        amp = 20.0 + (i / count) * 80.0
        patterns.append({
            "frequency": freq,
            "phase": phase,
            "amplitude": amp,
            "pattern_id": i,
        })
    return patterns


def _hammer_with_patterns(buffer_addr: int, row_offsets: list[int],
                          patterns: list[dict], activations_per_pattern: int = 1000000,
                          pin_core: int = 0):
    """Hammer rows using frequency-based patterns using native C code."""
    lib = get_lib()

    # Pin to specific core for consistent timing
    lib.sw_pin_to_core(pin_core)

    num_rows = len(row_offsets)
    row_addr_array = (ctypes.c_uint64 * num_rows)(*row_offsets)

    # Build native pattern structure
    class FreqPattern(ctypes.Structure):
        _fields_ = [
            ("frequency", ctypes.c_double),
            ("phase", ctypes.c_double),
            ("amplitude", ctypes.c_double),
            ("pattern_id", ctypes.c_int),
        ]

    class FreqPatternSet(ctypes.Structure):
        _fields_ = [
            ("num_patterns", ctypes.c_int),
            ("patterns", FreqPattern * 64),
        ]

    ps = FreqPatternSet()
    ps.num_patterns = min(len(patterns), 64)
    for i, p in enumerate(patterns[:64]):
        ps.patterns[i].frequency = p["frequency"]
        ps.patterns[i].phase = p["phase"]
        ps.patterns[i].amplitude = p["amplitude"]
        ps.patterns[i].pattern_id = p["pattern_id"]

    lib.sw_hammer_frequency(
        ctypes.c_void_p(buffer_addr),
        ctypes.cast(row_addr_array, ctypes.c_void_p),
        num_rows,
        ctypes.byref(ps),
        activations_per_pattern,
    )


def _check_for_flips(buffer_addr: int, size: int, initial_data: bytearray) -> list[FlipRecord]:
    """Check buffer for bit flips compared to initial data."""
    flips = []
    buf = ctypes.cast(ctypes.c_void_p(buffer_addr), ctypes.POINTER(ctypes.c_uint8))

    for offset in range(0, min(size, 256 * 1024 * 1024)):  # Check first 256MB
        current = buf[offset]
        initial = initial_data[offset % len(initial_data)]

        if current != initial:
            # Which bits flipped?
            xor_val = current ^ initial
            for bit in range(8):
                if xor_val & (1 << bit):
                    flips.append(FlipRecord(
                        address=buffer_addr + offset,
                        bit=bit,
                        from_byte=initial,
                        to_byte=current,
                    ))

    return flips


def run_rowhammer_fuzzer(timeout_minutes: int = 60,
                         region_mb: int = 256,
                         pin_core: int = 0) -> RowhammerResult:
    """
    Run Blacksmith-style frequency-based Rowhammer fuzzer.

    Args:
        timeout_minutes: Maximum duration for fuzzing
        region_mb: Memory region size in MB (default 256MB)
        pin_core: CPU core to pin the process to
    """
    start_time = time.time()
    deadline = start_time + timeout_minutes * 60

    dram_info = get_dram_info()
    result = RowhammerResult(dram_type=dram_info.get("dram_type", "Unknown"))

    if dram_info.get("dram_type") not in ["DDR3", "DDR4"]:
        result.error = f"Rowhammer primarily targets DDR3/DDR4. Detected: {dram_info['dram_type']}"
        return result

    try:
        buffer_addr, buffer_size = _allocate_hammer_region(region_mb)
    except RuntimeError as e:
        result.error = str(e)
        return result

    # Initialize buffer with known pattern (0x41 = 'A')
    buf_ptr = ctypes.cast(ctypes.c_void_p(buffer_addr), ctypes.POINTER(ctypes.c_uint8))
    initial_data = bytearray([0x41] * (4 * 1024 * 1024))  # 4MB sample
    for i in range(len(initial_data)):
        buf_ptr[i] = 0x41

    # Get DRAM address function to find same-bank rows
    lib = get_lib()
    bank_groups = discover_same_bank_rows(buffer_addr, buffer_size, max_rows=32)

    if not bank_groups:
        # Fall back to double-sided: hammer rows at distance 1 from victims
        # Use 2MB row stride, pick aggressors around victims
        row_size = HUGE_PAGE_SIZE
        num_rows = buffer_size // row_size
        aggressor_pairs = []
        for i in range(1, min(num_rows - 1, 31), 2):
            aggressor_pairs.append((i * row_size, (i + 1) * row_size))

        aggressors = [off for pair in aggressor_pairs for off in pair]
    else:
        # Use discovered bank groups
        aggressors = []
        for group in bank_groups[:8]:  # First 8 bank groups
            for row_idx in group:
                aggressors.append(row_idx * HUGE_PAGE_SIZE)

    result.rows_hammered = len(aggressors)

    # Generate Blacksmith patterns
    patterns = _generate_blacksmith_patterns(32)

    # Fuzz loop
    iteration = 0
    while time.time() < deadline:
        activations = 500000  # per pattern set per iteration

        _hammer_with_patterns(buffer_addr, aggressors, patterns,
                             activations_per_pattern=activations,
                             pin_core=pin_core)
        iteration += 1

        # Check for flips every few iterations
        if iteration % 5 == 0:
            new_flips = _check_for_flips(buffer_addr, buffer_size, initial_data)
            for f in new_flips:
                if not any(e.address == f.address and e.bit == f.bit
                          for e in result.flips):
                    result.flips.append(f)

            if result.flips:
                result.success = True
                result.total_activations += activations * iteration
                result.duration_sec = time.time() - start_time
                result.patterns_tried = min(len(patterns), iteration * len(patterns))
                break

        result.total_activations += activations

    result.duration_sec = time.time() - start_time
    result.patterns_tried = len(patterns)
    result.error = ""

    if not result.flips:
        result.error = f"No bit flips found after {timeout_minutes} minutes. "
        result.error += "Try longer duration, larger region, or different CPU core."

    # Cleanup
    lib.sw_free_huge_region(ctypes.c_void_p(buffer_addr), buffer_size)

    return result


def run_rowhammer_probe(timeout_minutes: int = 60, region_mb: int = 256) -> dict:
    """Run rowhammer probe and return structured results."""
    result = run_rowhammer_fuzzer(timeout_minutes=timeout_minutes,
                                 region_mb=region_mb)

    return {
        "success": result.success,
        "dram_type": result.dram_type,
        "flips_found": len(result.flips),
        "flips": [
            {
                "address": hex(f.address),
                "bit": f.bit,
                "from": f.from_byte,
                "to": f.to_byte,
            }
            for f in result.flips[:20]  # Cap at 20 for report
        ],
        "total_activations": result.total_activations,
        "duration_sec": result.duration_sec,
        "rows_hammered": result.rows_hammered,
        "error": result.error,
        "timestamp": time.time(),
    }
