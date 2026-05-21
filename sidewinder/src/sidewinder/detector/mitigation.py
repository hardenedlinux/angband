"""Mitigation status checker."""

import os

from sidewinder.detector.cpu import detect_vulnerability_status
from sidewinder.utils.system import kernel_version, kernel_version_tuple


MITIGATION_MAP = {
    "spectre_v1": "spectre_v1|Spectre v1|Bounds Check Bypass",
    "spectre_v2": "spectre_v2|Spectre v2|Branch Target Injection",
    "meltdown": "meltdown|Meltdown",
    "spec_store_bypass": "spec_store_bypass|Spectre v4|Speculative Store Bypass",
    "l1tf": "l1tf|Foreshadow|L1 Terminal Fault",
    "mds": "mds|ZombieLoad|RIDL|Fallout|Microarchitectural Data Sampling",
    "tsx_async_abort": "tsx_async_abort|TAA|TSX Asynchronous Abort",
    "itlb_multihit": "itlb_multihit|iTLB Multihit",
    "srbds": "srbds|CROSSTalk|Special Register Buffer Data Sampling",
    "mmio_stale_data": "mmio_stale_data|MMIO Stale Data",
    "retbleed": "retbleed|Retbleed",
    "spec_rstack_overflow": "spec_rstack_overflow|Inception|SRSO",
    "gather_data_sampling": "gather_data_sampling|Downfall|GDS",
    "reg_file_data_sampling": "reg_file_data_sampling|RFDS",
    "branch_history_injection": "branch_history_injection|BHI",
    "spectre_bhb": "spectre_bhb|BHI|Branch History Injection",
    "zenbleed": "zenbleed|Zenbleed",
}


VULNERABLE_STATUSES = {
    "Vulnerable",
    "Vulnerable: No microcode",
    "Vulnerable; __user pointer sanitization and usercopy barriers only; no swapgs barriers",
}


def check_mitigation_status() -> dict:
    status = detect_vulnerability_status()
    kernel_ver = kernel_version()
    kv_tuple = kernel_version_tuple()

    results = {}
    for key, value in status.items():
        if not isinstance(value, str):
            continue
        is_vulnerable = any(vs in value for vs in VULNERABLE_STATUSES)
        is_mitigated = not is_vulnerable and value != "unreadable"

        results[key] = {
            "status": value,
            "vulnerable": is_vulnerable,
            "mitigated": is_mitigated,
            "known": value != "unreadable",
        }

    return {
        "kernel_version": kernel_ver,
        "kernel_tuple": kv_tuple,
        "vulnerabilities": results,
    }
