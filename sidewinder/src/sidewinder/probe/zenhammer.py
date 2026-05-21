"""ZenHammer probe - AMD Zen DDR5 Rowhammer.

ZenHammer is a Rowhammer variant specifically targeting AMD Zen 2/3/4
processors with DDR4/DDR5 memory. It uses aggressive row-conflict patterns
that exploit AMD's memory controller behavior.

Based on: "ZenHammer: Rowhammer on AMD Zen-based Platforms" (2024)
"""

import ctypes
import mmap
import time
from sidewinder.primitives.native import get_lib


def run_zenhammer_probe(timeout_minutes: int = 30, region_mb: int = 256) -> dict:
    """Run ZenHammer probe on AMD Zen platforms."""
    lib = get_lib()

    # Allocate buffer
    region_size = region_mb * 1024 * 1024
    buf = mmap.mmap(-1, region_size,
                    prot=mmap.PROT_READ | mmap.PROT_WRITE,
                    flags=mmap.MAP_PRIVATE | mmap.MAP_ANONYMOUS | mmap.MAP_POPULATE)

    # Fill with pattern
    buf.write(b'A' * region_size)
    buf.flush()

    buf_addr = ctypes.addressof(ctypes.c_char.from_buffer(buf))

    # Setup row addresses (simulate contiguous rows)
    num_rows = min(64, region_size // 4096)
    row_addrs = (ctypes.c_uint64 * num_rows)()
    for i in range(num_rows):
        row_addrs[i] = i * 4096

    start = time.time()
    total_activations = 0

    try:
        # Detect AMD family
        with open('/proc/cpuinfo', 'r') as f:
            cpuinfo = f.read()
            family_match = __import__('re').search(r'cpu family\s*:\s*(\d+)', cpuinfo)
            amd_family = int(family_match.group(1)) if family_match else 25

        # Run ZenHammer
        aggressors_per_set = 4
        total_activations = 1000000

        lib.sw_zenhammer_hammer(
            ctypes.c_void_p(buf_addr),
            ctypes.cast(row_addrs, ctypes.c_void_p),
            num_rows,
            aggressors_per_set,
            total_activations,
            amd_family
        )

        # Check for flips
        result = hammer_result_t()
        num_flips = lib.sw_check_flips(ctypes.c_void_p(buf_addr), region_size, ctypes.byref(result))

        duration = time.time() - start

        flips = []
        for i in range(min(num_flips, 10)):
            flips.append({
                "address": hex(result.flips[i].addr),
                "bit": result.flips[i].bit_pos,
                "from": result.flips[i].from_val,
                "to": result.flips[i].to_val,
            })

        return {
            "success": num_flips > 0,
            "flips_found": num_flips,
            "flips": flips,
            "duration_sec": duration,
            "total_activations": total_activations,
            "amd_family": amd_family,
            "error": None,
        }

    except Exception as e:
        return {
            "success": False,
            "flips_found": 0,
            "flips": [],
            "duration_sec": time.time() - start,
            "total_activations": total_activations,
            "error": str(e),
        }
    finally:
        buf.close()


class hammer_result_t(ctypes.Structure):
    _fields_ = [
        ("num_flips", ctypes.c_int),
        ("flips", ctypes.c_ubyte * (4096 * 4)),  # MAX_FLIPS * sizeof(flip_record_t)
        ("total_activations", ctypes.c_uint64),
        ("duration_sec", ctypes.c_double),
    ]
