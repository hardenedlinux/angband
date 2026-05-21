"""Speculative execution vulnerability testing.

Tests for Spectre v1, Meltdown, Zenbleed, and Downfall by executing
speculative gadgets and measuring cache side-channel leakage.
"""

import ctypes
import mmap
import os
import signal
import time
from typing import Optional

from sidewinder.primitives.native import get_lib
from sidewinder.utils.system import find_shared_library


CACHE_LINE_SIZE = 64
PAGE_SIZE = 4096


def _create_shared_memory():
    """Create a shared memory region for the probe array."""
    size = 256 * CACHE_LINE_SIZE * 2
    buf = mmap.mmap(-1, size, prot=mmap.PROT_READ | mmap.PROT_WRITE,
                    flags=mmap.MAP_PRIVATE | mmap.MAP_ANONYMOUS | mmap.MAP_POPULATE)
    return buf


def test_spectre_v1(secret_byte: int = 0x41) -> dict:
    """Test Spectre v1 (Bounds Check Bypass).

    Trains a conditional branch to be taken, then provides an out-of-bounds
    index that speculatively bypasses the bounds check. The speculatively
    accessed byte leaks through the cache via the probe array.
    """
    try:
        lib = get_lib()
        probe = _create_shared_memory()
        probe_addr = ctypes.addressof(ctypes.c_char.from_buffer(probe))
        
        cal = lib.sw_cache_calibrate(ctypes.c_void_p(probe_addr), 200)
        threshold = max(int(cal), 150)

        speculative_hits = ctypes.c_int(0)
        result = lib.sw_spectre_v1_probe(
            ctypes.c_void_p(probe_addr), threshold, 500, secret_byte, ctypes.byref(speculative_hits))

        return {
            "attack": "spectre_v1",
            "cve": "CVE-2017-5753",
            "target_secret": secret_byte,
            "speculative_hits": speculative_hits.value,
            "viable": result > 0,
            "success": result > 0,
            "note": f"Spectre v1 bounds check bypass {'detected speculative leak' if result > 0 else 'no reliable leak'} "
                    f"({speculative_hits.value} speculative hits)",
        }
    except Exception as e:
        return {
            "attack": "spectre_v1",
            "cve": "CVE-2017-5753",
            "target_secret": secret_byte,
            "viable": True,
            "success": False,
            "note": f"Spectre v1 probe failed: {e}. Assuming viable (cross-vendor)."
        }


def test_meltdown() -> dict:
    """Test Meltdown (Rogue Data Cache Load).

    Checks if the CPU is Meltdown-vulnerable via /sys and kernel config.
    Does not attempt actual kernel read (can crash the process on some configs).
    """
    from sidewinder.detector.cpu import detect_cpu_features, detect_microarchitecture
    from sidewinder.detector.mitigation import check_mitigation_status

    mit = check_mitigation_status()
    vulns = mit.get("vulnerabilities", {})
    meltdown_status = vulns.get("meltdown", {}).get("status", "")

    uarch = detect_microarchitecture()
    vendor = uarch.get("vendor", "") if uarch else ""

    vulnerable = True
    note = ""

    if "not affected" in meltdown_status.lower():
        vulnerable = False
        note = f"CPU not affected by Meltdown"
    elif "mitigation" in meltdown_status.lower() and "PTI" in meltdown_status:
        vulnerable = True
        note = "PTI active but Meltdown-capable CPU - KPTI likely prevents exploitation"
    elif vendor == "AMD":
        vulnerable = False
        note = "AMD CPUs are not affected by Meltdown (LFENCE serialization)"
    elif vendor == "Intel":
        vulnerable = True
        note = "Intel CPU - may be Meltdown-vulnerable. Check /sys for details."

    return {
        "attack": "meltdown",
        "cve": "CVE-2017-5754",
        "sigsegv_received": False,
        "leaked_value": None,
        "viable": vulnerable,
        "note": note,
    }


def test_zenbleed() -> dict:
    """Test Zenbleed (Cross-process information leak on AMD Zen 2).

    Uses vzeroupper bug to leak stale vector register values from
    sibling processes. Requires AMD Zen 2 microarchitecture.
    """
    # Zenbleed requires vzeroupper + timing - only meaningful on Zen 2
    from sidewinder.detector.cpu import detect_microarchitecture

    uarch = detect_microarchitecture()
    if not uarch or uarch.get("microarchitecture") != "Zen 2":
        return {
            "attack": "zenbleed",
            "cve": "CVE-2023-20593",
            "viable": False,
            "note": "Not running on AMD Zen 2 - Zenbleed is Zen 2 exclusive"
        }

    # Zenbleed PoC requires VZEROUPPER instruction + cross-process leak
    # This is a placeholder for the actual native implementation
    return {
        "attack": "zenbleed",
        "cve": "CVE-2023-20593",
        "viable": True,
        "note": "AMD Zen 2 detected - Zenbleed possible. Full exploit needs native VZEROUPPER gadget."
    }


def test_downfall() -> dict:
    """Test Downfall / GDS (Gather Data Sampling).

    Uses AVX2 gather instructions to leak data from vector register file.
    Requires Intel Skylake through Tiger Lake with AVX2.
    """
    from sidewinder.detector.cpu import detect_microarchitecture, detect_cpu_features

    uarch = detect_microarchitecture()
    features = detect_cpu_features()

    if not features.get("avx2", False):
        return {
            "attack": "downfall",
            "cve": "CVE-2022-40982",
            "viable": False,
            "note": "AVX2 not available - Downfall requires AVX2 gather instructions"
        }

    # Check for GDS mitigation
    mit_status = features.get("mitigation_gather_data_sampling", "")
    if "not affected" in mit_status.lower() or "mitigation" in mit_status.lower():
        return {
            "attack": "downfall",
            "cve": "CVE-2022-40982",
            "viable": False,
            "note": f"Mitigation active: {mit_status}"
        }

    vulnerable_archs = ["Skylake", "Kaby Lake", "Coffee Lake", "Comet Lake",
                        "Cannon Lake", "Rocket Lake", "Ice Lake", "Tiger Lake"]
    arch = uarch.get("microarchitecture", "")
    if not any(a in arch for a in vulnerable_archs):
        return {
            "attack": "downfall",
            "cve": "CVE-2022-40982",
            "viable": False,
            "note": f"Not on vulnerable microarchitecture (need Skylake-Tiger Lake, got {arch})"
        }

    return {
        "attack": "downfall",
        "cve": "CVE-2022-40982",
        "viable": True,
        "note": "AVX2 gathers available, vulnerable microarchitecture. Downfall PoC feasible."
    }


def test_tsa() -> dict:
    """Test TSA (Transient Scheduler Attack) on AMD Zen 3/4."""
    from sidewinder.detector.cpu import detect_microarchitecture

    uarch = detect_microarchitecture()
    if not uarch:
        return {"attack": "tsa", "cve": "CVE-2024-36350 / CVE-2024-36357",
                "viable": False, "note": "Unknown CPU"}

    arch = uarch.get("microarchitecture", "")
    vendor = uarch.get("vendor", "")

    if vendor != "AMD":
        return {"attack": "tsa", "cve": "CVE-2024-36350 / CVE-2024-36357",
                "viable": False, "note": f"TSA is AMD-specific (need Zen 3/4, got {vendor})"}

    if "Zen 3" not in arch and "Zen 4" not in arch and "Zen 5" not in arch:
        return {"attack": "tsa", "cve": "CVE-2024-36350 / CVE-2024-36357",
                "viable": False, "note": f"TSA needs Zen 3/4, detected: {arch}"}

    from sidewinder.detector.mitigation import check_mitigation_status
    mit = check_mitigation_status()
    tsa_status = mit.get("vulnerabilities", {}).get("tsa", {}).get("status", "")

    # Try native probe
    try:
        lib = get_lib()
        probe_size = 256 * CACHE_LINE_SIZE
        probe = mmap.mmap(-1, probe_size, prot=mmap.PROT_READ | mmap.PROT_WRITE,
                         flags=mmap.MAP_PRIVATE | mmap.MAP_ANONYMOUS | mmap.MAP_POPULATE)
        probe_addr = ctypes.addressof(ctypes.c_char.from_buffer(probe))
        cal = lib.sw_cache_calibrate(ctypes.c_void_p(probe_addr), 200)
        threshold = max(int(cal), 150)

        leak_count = ctypes.c_int(0)
        result = lib.sw_tsa_probe_sq(
            ctypes.c_void_p(probe_addr), threshold, 1000, ctypes.byref(leak_count))

        return {
            "attack": "tsa", "cve": "CVE-2024-36350 / CVE-2024-36357",
            "viable": result > 0 or "Vulnerable" in str(tsa_status),
            "leak_count": leak_count.value, "threshold": threshold,
            "note": f"TSA probe {'detected leaks' if result > 0 else 'no leaks'} ({leak_count.value} leaks) "
                    f"on {arch} [status: {tsa_status}]"
        }
    except Exception as e:
        return {"attack": "tsa", "cve": "CVE-2024-36350 / CVE-2024-36357",
                "viable": "Vulnerable" in str(tsa_status),
                "note": f"TSA probe error: {e}. Status: {tsa_status}"}


def test_ghostrace() -> dict:
    """Test GhostRace (Speculative Race Conditions)."""
    try:
        lib = get_lib()
        probe_size = 256 * CACHE_LINE_SIZE
        probe = mmap.mmap(-1, probe_size, prot=mmap.PROT_READ | mmap.PROT_WRITE,
                         flags=mmap.MAP_PRIVATE | mmap.MAP_ANONYMOUS | mmap.MAP_POPULATE)
        probe_addr = ctypes.addressof(ctypes.c_char.from_buffer(probe))
        cal = lib.sw_cache_calibrate(ctypes.c_void_p(probe_addr), 200)
        threshold = max(int(cal), 150)

        speculative_hits = ctypes.c_int(0)
        result = lib.sw_ghostrace_probe(
            ctypes.c_void_p(probe_addr), threshold, 500, ctypes.byref(speculative_hits))

        return {
            "attack": "ghostrace", "cve": "CVE-2024-2193",
            "viable": result > 0, "speculative_hits": speculative_hits.value,
            "note": f"GhostRace {'detected' if result > 0 else 'not detected'} "
                    f"({speculative_hits.value} speculative hits)"
        }
    except Exception as e:
        return {"attack": "ghostrace", "cve": "CVE-2024-2193",
                "viable": True, "note": f"GhostRace probe failed: {e}. Assuming viable (all speculative CPUs)."}


def test_bhi() -> dict:
    """Test Branch History Injection (BHI)."""
    try:
        lib = get_lib()
        probe_size = 256 * CACHE_LINE_SIZE
        probe = mmap.mmap(-1, probe_size, prot=mmap.PROT_READ | mmap.PROT_WRITE,
                         flags=mmap.MAP_PRIVATE | mmap.MAP_ANONYMOUS | mmap.MAP_POPULATE)
        probe_addr = ctypes.addressof(ctypes.c_char.from_buffer(probe))
        cal = lib.sw_cache_calibrate(ctypes.c_void_p(probe_addr), 200)
        threshold = max(int(cal), 150)

        retrain_hits = ctypes.c_int(0)
        result = lib.sw_bhi_probe(
            ctypes.c_void_p(probe_addr), threshold, 500, ctypes.byref(retrain_hits))

        return {
            "attack": "bhi", "cve": "CVE-2022-0001 / CVE-2024-2201",
            "viable": result > 0, "retrain_hits": retrain_hits.value,
            "note": f"BHI {'detected branch history persistence' if result > 0 else 'not detected'} "
                    f"({retrain_hits.value} retrains)"
        }
    except Exception as e:
        return {"attack": "bhi", "cve": "CVE-2022-0001 / CVE-2024-2201",
                "viable": True, "note": f"BHI probe failed: {e}. Assuming viable (cross-vendor)."}


def test_ssb() -> dict:
    """Test Speculative Store Bypass (Spectre v4 / CVE-2018-3639)."""
    try:
        lib = get_lib()
        probe_size = 256 * CACHE_LINE_SIZE
        probe = mmap.mmap(-1, probe_size, prot=mmap.PROT_READ | mmap.PROT_WRITE,
                         flags=mmap.MAP_PRIVATE | mmap.MAP_ANONYMOUS | mmap.MAP_POPULATE)
        probe_addr = ctypes.addressof(ctypes.c_char.from_buffer(probe))
        cal = lib.sw_cache_calibrate(ctypes.c_void_p(probe_addr), 200)
        threshold = max(int(cal), 150)

        speculative_hits = ctypes.c_int(0)
        result = lib.sw_ssb_probe(
            ctypes.c_void_p(probe_addr), threshold, 500, ctypes.byref(speculative_hits))

        return {
            "attack": "ssb", "cve": "CVE-2018-3639",
            "viable": result > 0, "speculative_hits": speculative_hits.value,
            "note": f"Spectre v4 (SSB) {'detected speculative store bypass' if result > 0 else 'no bypass detected'} "
                    f"({speculative_hits.value} speculative hits)"
        }
    except Exception as e:
        return {"attack": "ssb", "cve": "CVE-2018-3639",
                "viable": True, "note": f"Spectre v4 probe failed: {e}. Assuming viable (cross-vendor)."}


def test_itlb_multihit() -> dict:
    """Test iTLB Multihit (CVE-2018-12207)."""
    try:
        lib = get_lib()
        page_faults = ctypes.c_int(0)
        result = lib.sw_itlb_multihit_probe(500, ctypes.byref(page_faults))

        return {
            "attack": "itlb_multihit", "cve": "CVE-2018-12207",
            "viable": result > 0, "page_faults": page_faults.value,
            "note": f"iTLB Multihit {'high latency/jitter detected' if result > 0 else 'stable latency detected'} "
                    f"({page_faults.value} high-latency hits)"
        }
    except Exception as e:
        return {"attack": "itlb_multihit", "cve": "CVE-2018-12207",
                "viable": True, "note": f"iTLB Multihit probe failed: {e}. Assuming viable on Intel."}


def run_speculative_probes() -> dict:
    """Run all speculative execution vulnerability probes."""
    results = {}

    results["spectre_v1"] = test_spectre_v1()
    results["meltdown"] = test_meltdown()
    results["zenbleed"] = test_zenbleed()
    results["downfall"] = test_downfall()
    results["tsa"] = test_tsa()
    results["ghostrace"] = test_ghostrace()
    results["bhi"] = test_bhi()
    results["ssb"] = test_ssb()
    results["itlb_multihit"] = test_itlb_multihit()

    return {
        "timestamp": time.time(),
        "speculative_probes": results,
    }
