"""Hertzbleed probe - DVFS timing side-channel detection.

Hertzbleed (CVE-2022-23823, CVE-2022-24436) exploits CPU frequency scaling.
Certain data patterns cause higher power draw, leading to thermal throttling
that changes execution timing. This probe detects if the system exhibits
such leakage.

Affected: Intel 10th-12th gen, AMD Zen 2/3/4 with DVFS enabled.
"""

import ctypes
import time
from sidewinder.primitives.native import get_lib


def run_hertzbleed_probe(samples: int = 1000) -> dict:
    """Run Hertzbleed probe and return results."""
    lib = get_lib()

    leaks = ctypes.c_int(0)
    start = time.time()

    result = lib.sw_hertzbleed_probe(samples, ctypes.byref(leaks))

    duration = time.time() - start

    # Interpret results
    vulnerable = (result == 1)
    timing_delta = leaks.value * 10 if leaks.value > 0 else 0

    note = ""
    if vulnerable:
        note = (
            f"DVFS leakage detected: {timing_delta} cycle delta between "
            f"low-power and high-power data patterns. "
            f"This indicates the CPU throttles frequency based on data-dependent power draw."
        )
    else:
        note = (
            "No significant DVFS timing variation detected. "
            "CPU may have fixed frequency, or DVFS is too coarse to measure."
        )

    return {
        "vulnerable": vulnerable,
        "timing_delta": timing_delta,
        "leak_indicators": leaks.value,
        "duration_sec": duration,
        "samples": samples,
        "cve": "CVE-2022-23823 / CVE-2022-24436",
        "note": note,
    }
