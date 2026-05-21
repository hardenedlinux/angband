"""Cache side-channel active probe using native C primitives.

Performs auto-calibration of cache hit/miss thresholds and demonstrates
Flush+Reload, Prime+Probe, and Evict+Time primitives on a shared library.
"""

import ctypes
import mmap
import os
import sys
import time
from typing import Optional

from sidewinder.primitives.native import get_lib
from sidewinder.utils.system import find_shared_library


CACHE_LINE_SIZE = 64


def calibrate_threshold(addr: int = 0, trials: int = 1000) -> dict:
    """Auto-calibrate cache hit/miss timing threshold.

    Returns a dict with threshold, hit_avg, miss_avg, and calibration quality.
    """
    lib = get_lib()

    # Allocate a page we can flush and reload
    if addr == 0:
        buf = mmap.mmap(-1, 4096, prot=mmap.PROT_READ | mmap.PROT_WRITE,
                        flags=mmap.MAP_PRIVATE | mmap.MAP_ANONYMOUS)
        buf[0] = 1
        addr_int = ctypes.addressof(ctypes.c_char.from_buffer(buf))
    else:
        buf = None
        addr_int = addr

    hits = []
    misses = []

    for _ in range(trials):
        # Hit measurement
        lib.sw_mfence()
        _ = ctypes.c_uint8.from_address(addr_int).value  # bring into cache
        lib.sw_mfence()
        t_hit = lib.sw_reload_line(ctypes.c_void_p(addr_int))
        hits.append(t_hit)

    for _ in range(trials):
        # Miss measurement
        lib.sw_flush_line(ctypes.c_void_p(addr_int))
        t_miss = lib.sw_reload_line(ctypes.c_void_p(addr_int))
        misses.append(t_miss)

    hits.sort()
    misses.sort()

    hit_avg = sum(hits) / len(hits)
    miss_avg = sum(misses) / len(misses)
    hit_median = hits[len(hits) // 2]
    miss_median = misses[len(misses) // 2]

    # Threshold: midpoint of medians, plus small buffer
    threshold = max(hit_median + 20, (hit_median + miss_median) // 2)

    # Quality: how well separated are hit and miss distributions?
    # Good quality: hit_median < threshold < miss_median with large gap
    gap = miss_median - hit_median
    quality = "excellent" if gap > 100 else ("good" if gap > 50 else
              ("fair" if gap > 20 else "poor"))

    # Also do native calibration as double-check
    native_threshold = lib.sw_cache_calibrate(ctypes.c_void_p(addr_int), 256)

    return {
        "threshold": threshold,
        "native_threshold": native_threshold,
        "hit_avg": hit_avg,
        "miss_avg": miss_avg,
        "hit_median": hit_median,
        "miss_median": miss_median,
        "gap": gap,
        "quality": quality,
        "trials": trials,
    }


def flush_reload_test(lib_path: str = "", threshold: int = 0) -> dict:
    """Test Flush+Reload on a shared library.

    Monitors cache hits on every 64-byte cache line of the target library.
    High cache hit rate means the library's memory is accessible for
    side-channel observation.
    """
    lib = get_lib()

    if not lib_path:
        lib_path = find_shared_library("libc.so.6")
    if not lib_path:
        return {"error": "No shared library found for Flush+Reload test"}

    fd = os.open(lib_path, os.O_RDONLY)
    stat = os.fstat(fd)
    size = stat.st_size

    buf = mmap.mmap(fd, size, prot=mmap.PROT_READ | mmap.PROT_WRITE,
                    flags=mmap.MAP_PRIVATE)
    os.close(fd)

    if threshold == 0:
        calib = calibrate_threshold()
        threshold = calib["threshold"]

    # Probe every 64-byte cache line in the first 64KB of text
    probe_size = min(size, 65536)
    text_offset = 0  # For a real library we'd parse ELF .text section
    hits = 0
    misses = 0
    total = 0

    base_addr = ctypes.addressof(ctypes.c_char.from_buffer(buf))
    for offset in range(text_offset, text_offset + probe_size, CACHE_LINE_SIZE):
        addr = ctypes.c_void_p(base_addr + offset)
        t = lib.sw_reload_line(addr)
        total += 1
        if t < threshold:
            hits += 1
        else:
            misses += 1

    hit_rate = (hits / total * 100) if total > 0 else 0

    return {
        "library": lib_path,
        "probed_size": probe_size,
        "cache_lines_probed": total,
        "hits": hits,
        "misses": misses,
        "hit_rate_pct": round(hit_rate, 2),
        "threshold": threshold,
        "side_channel_viable": hit_rate > 5.0,
    }


def prime_probe_test(size_kb: int = 4096) -> dict:
    """Test Prime+Probe by creating an eviction buffer and measuring probe latency."""
    lib = get_lib()

    size = size_kb * 1024
    buf = mmap.mmap(-1, size + CACHE_LINE_SIZE,
                    prot=mmap.PROT_READ | mmap.PROT_WRITE,
                    flags=mmap.MAP_PRIVATE | mmap.MAP_ANONYMOUS | mmap.MAP_POPULATE)
    addr = ctypes.addressof(ctypes.c_char.from_buffer(buf))

    stride = CACHE_LINE_SIZE
    ways = 16
    sets = size // (stride * ways)

    # Prime the entire buffer
    for s in range(min(sets, 256)):
        lib.sw_prime_set(ctypes.c_void_p(addr), s, stride, ways)

    # Probe timing
    probe_times = []
    for s in range(min(sets, 256)):
        hits = lib.sw_probe_set(ctypes.c_void_p(addr), s, stride, ways)
        probe_times.append(hits)

    avg_hits = sum(probe_times) / len(probe_times) if probe_times else 0

    # Now evict a random set and check if probe detects it
    test_set = sets // 2
    lib.sw_evict_set(ctypes.c_void_p(addr), test_set, stride, ways)
    post_evict_hits = lib.sw_probe_set(ctypes.c_void_p(addr), test_set, stride, ways)

    return {
        "buffer_size_kb": size_kb,
        "sets": sets,
        "ways": ways,
        "avg_primed_hits": round(avg_hits, 2),
        "post_evict_hits": post_evict_hits,
        "eviction_detectable": post_evict_hits < avg_hits,
        "side_channel_viable": avg_hits >= ways * 0.6,
    }


def run_side_channel_probe() -> dict:
    """Run all cache side-channel probes and return results."""
    libc = find_shared_library("libc.so.6")

    calib = calibrate_threshold()

    fr_result = None
    if libc:
        fr_result = flush_reload_test(libc, calib["threshold"])

    pp_result = prime_probe_test()

    return {
        "calibration": calib,
        "flush_reload": fr_result,
        "prime_probe": pp_result,
        "timestamp": time.time(),
    }
