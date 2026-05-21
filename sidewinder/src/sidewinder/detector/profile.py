"""Vulnerability profile matching for CPU/microarchitecture.

Maps detected CPU features and microarchitecture to known CVE profiles.
Loaded from profiles/cpu/known_cves.json and augmented with runtime checks.
"""

import json
import os
from pathlib import Path
from typing import Any

# Inline CVE knowledge base - maps microarchitecture patterns to CVEs
# Format: (vendor_pattern, arch_pattern, feature_required, feature_forbidden, cve_id, severity, attack_class)


CVES = [
    # Meltdown family - Intel pre-Ice Lake
    {"cve": "CVE-2017-5754", "name": "Meltdown", "class": "meltdown",
     "vendor": "Intel", "arch_filter": "!Ice Lake|!Tiger Lake|!Alder Lake|!Raptor Lake|!Meteor Lake|!Lunar Lake|!Arrow Lake|!Sapphire Rapids|!Emerald Rapids",
     "severity": "HIGH", "privilege": "unprivileged",
     "description": "Rogue Data Cache Load - reads kernel memory from userspace"},

    {"cve": "CVE-2017-5753", "name": "Spectre v1", "class": "spectre",
     "vendor": "Intel|AMD|ARM", "arch_filter": "!",
     "severity": "MEDIUM", "privilege": "unprivileged",
     "description": "Bounds Check Bypass - speculative branch misprediction leaks data via cache"},

    {"cve": "CVE-2017-5715", "name": "Spectre v2", "class": "spectre",
     "vendor": "Intel|AMD|ARM", "arch_filter": "!",
     "severity": "HIGH", "privilege": "unprivileged",
     "description": "Branch Target Injection - poisons BTB to redirect speculative execution"},

    {"cve": "CVE-2018-3639", "name": "Spectre v4 / SSB", "class": "spectre",
     "vendor": "Intel|AMD|ARM", "arch_filter": "!",
     "severity": "MEDIUM", "privilege": "unprivileged",
     "description": "Speculative Store Bypass - speculative loads bypass older stores"},

    {"cve": "CVE-2018-3615", "name": "Foreshadow / L1TF", "class": "meltdown",
     "vendor": "Intel", "arch_filter": "!Ice Lake|!Tiger Lake|!Alder Lake|!Raptor Lake|!Meteor Lake|!Lunar Lake|!Arrow Lake",
     "severity": "HIGH", "privilege": "unprivileged",
     "description": "L1 Terminal Fault - SGX/OS/SMM memory leak via L1 cache"},

    {"cve": "CVE-2018-12130", "name": "ZombieLoad / MDS", "class": "mds",
     "vendor": "Intel", "arch_filter": "!Ice Lake|!Tiger Lake|!Alder Lake|!Raptor Lake|!Meteor Lake|!Lunar Lake|!Arrow Lake|!Sapphire Rapids|!Emerald Rapids",
     "severity": "HIGH", "privilege": "unprivileged",
     "description": "MFBDS - data leak from line fill buffers on Intel CPUs"},

    {"cve": "CVE-2019-11135", "name": "TAA / ZombieLoad v2", "class": "mds",
     "vendor": "Intel", "arch_filter": "!Ice Lake|!Tiger Lake|!Alder Lake|!Raptor Lake|!Meteor Lake|!Lunar Lake|!Arrow Lake",
     "feature": "tsx",
     "severity": "HIGH", "privilege": "unprivileged",
     "description": "TSX Asynchronous Abort - LFB data leak via TSX abort"},

    {"cve": "CVE-2020-0543", "name": "CROSSTalk / SRBDS", "class": "mds",
     "vendor": "Intel", "arch_filter": "!Comet Lake|!Rocket Lake|!Alder Lake|!Raptor Lake|!Meteor Lake|!Lunar Lake|!Arrow Lake|!Ice Lake|!Tiger Lake",
     "severity": "MEDIUM", "privilege": "unprivileged",
     "description": "Special Register Buffer Data Sampling - leaks RDRAND/RDSEED output"},

    {"cve": "CVE-2022-29900", "name": "Retbleed (Intel)", "class": "spectre",
     "vendor": "Intel", "arch_filter": "Skylake|Kaby Lake|Coffee Lake|Comet Lake|Whiskey Lake",
     "severity": "HIGH", "privilege": "unprivileged",
     "description": "Return Stack Buffer overflow enables speculative kernel gadget execution"},

    {"cve": "CVE-2022-29901", "name": "Retbleed (AMD)", "class": "spectre",
     "vendor": "AMD", "arch_filter": "Zen 1|Zen+|Zen 2",
     "severity": "HIGH", "privilege": "unprivileged",
     "description": "Return Stack Buffer overflow enables speculative kernel gadget execution (AMD)"},

    {"cve": "CVE-2022-0001", "name": "Branch History Injection", "class": "spectre",
     "vendor": "Intel|AMD|ARM",
     "severity": "HIGH", "privilege": "unprivileged",
     "description": "BHI - Branch History Buffer poisoning across privilege boundaries"},

    {"cve": "CVE-2022-40982", "name": "Downfall / GDS", "class": "mds",
     "vendor": "Intel",
     "arch_filter": "Skylake|Kaby Lake|Coffee Lake|Comet Lake|Cannon Lake|Rocket Lake|Ice Lake|Tiger Lake",
     "feature": "avx2",
     "severity": "HIGH", "privilege": "unprivileged",
     "description": "Gather Data Sampling - leaking vector register data via AVX gather instructions"},

    {"cve": "CVE-2023-20593", "name": "Zenbleed", "class": "side_channel",
     "vendor": "AMD", "arch_filter": "Zen 2",
     "severity": "HIGH", "privilege": "unprivileged",
     "description": "Vector register renaming bug leaks register contents cross-process on Zen 2"},

    {"cve": "CVE-2023-20569", "name": "Inception / SRSO", "class": "spectre",
     "vendor": "AMD", "arch_filter": "Zen 1|Zen+|Zen 2|Zen 3|Zen 4",
     "feature": "smt",
     "severity": "MEDIUM", "privilege": "unprivileged",
     "description": "Speculative Return Stack Overflow - phantom speculation via RSB misprediction"},

    {"cve": "CVE-2024-2193", "name": "GhostRace", "class": "spectre",
     "vendor": "Intel|AMD|ARM",
     "severity": "MEDIUM", "privilege": "unprivileged",
     "description": "Speculative race conditions - speculative execution past synchronization primitives"},

    {"cve": "CVE-2024-2201", "name": "Native BHI", "class": "spectre",
     "vendor": "Intel|ARM",
     "arch_filter": "Alder Lake|Raptor Lake|Sapphire Rapids",
     "severity": "HIGH", "privilege": "unprivileged",
     "description": "Userspace-only Branch History Injection via eBPF and userland gadgets"},

    {"cve": "CVE-2023-28746", "name": "RFDS", "class": "mds",
     "vendor": "Intel", "arch_filter": "Gracemont|Tremont|Goldmont|Silvermont|Airmont",
     "severity": "MEDIUM", "privilege": "unprivileged",
     "description": "Register File Data Sampling on Intel Atom E-cores"},

    {"cve": "CVE-2024-45332", "name": "Branch Privilege Injection", "class": "spectre",
     "vendor": "Intel", "arch_filter": "Coffee Lake|Comet Lake|Rocket Lake|Alder Lake|Raptor Lake|Meteor Lake|Sapphire Rapids|Emerald Rapids",
     "severity": "HIGH", "privilege": "unprivileged",
     "description": "Branch predictor privilege-level leakage between rings"},

    {"cve": "CVE-2024-36350", "name": "TSA-SQ", "class": "side_channel",
     "vendor": "AMD", "arch_filter": "Zen 3|Zen 4",
     "severity": "MEDIUM", "privilege": "unprivileged",
     "description": "Transient Scheduler Attack - Store Queue data leak on AMD Zen 3/4"},

    {"cve": "CVE-2024-36357", "name": "TSA-L1", "class": "side_channel",
     "vendor": "AMD", "arch_filter": "Zen 3|Zen 4",
     "severity": "MEDIUM", "privilege": "unprivileged",
     "description": "Transient Scheduler Attack - L1 data leak on AMD Zen 3/4"},

    {"cve": "CVE-2024-28956", "name": "ITS (Indirect Target Selection)", "class": "spectre",
     "vendor": "Intel", "arch_filter": "Coffee Lake|Comet Lake|Rocket Lake|Ice Lake|Tiger Lake",
     "severity": "HIGH", "privilege": "unprivileged",
     "description": "Indirect branch target prediction steering via BHB manipulation on Intel 9th-11th gen"},

    {"cve": "CVE-2025-24495", "name": "Lion Cove BPU Issue", "class": "spectre",
     "vendor": "Intel", "arch_filter": "Lunar Lake|Arrow Lake|Panther Lake",
     "severity": "HIGH", "privilege": "unprivileged",
     "description": "Branch predictor state injection targeting Lion Cove core"},

    {"cve": "CVE-2025-54505", "name": "FP-DSS (Floating Point Divider State Sampling)", "class": "side_channel",
     "vendor": "AMD", "arch_filter": "Zen 1|Zen+|Zen 2|Zen 3|Zen 4",
     "severity": "MEDIUM", "privilege": "unprivileged",
     "description": "Speculative FP division leaks stale data from internal FP divider state"},

    {"cve": "CVE-2025-40300", "name": "VMScape", "class": "spectre",
     "vendor": "AMD|Intel", "arch_filter": "Zen 1|Zen 2|Zen 3|Zen 4|Zen 5|Coffee Lake",
     "severity": "HIGH", "privilege": "guest-vm",
     "description": "Spectre-BTI across VM boundaries — guest trains branch predictor to leak host hypervisor memory"},

    {"cve": "CVE-2024-36348", "name": "TSA-CR", "class": "side_channel",
     "vendor": "AMD", "arch_filter": "Zen 3|Zen 4",
     "severity": "MEDIUM", "privilege": "unprivileged",
     "description": "Transient Scheduler Attack - Control Register value leak on AMD Zen 3/4"},

    {"cve": "CVE-2022-23823", "name": "Hertzbleed", "class": "side_channel",
     "vendor": "Intel|AMD", "arch_filter": "!",
     "severity": "MEDIUM", "privilege": "unprivileged",
     "description": "DVFS timing side-channel - data-dependent power draw leaks through CPU frequency scaling"},

    {"cve": "CVE-2024-XXXXX", "name": "ZenHammer", "class": "rowhammer",
     "vendor": "AMD", "arch_filter": "Zen 2|Zen 3|Zen 4|Zen 5",
     "severity": "HIGH", "privilege": "unprivileged",
     "description": "Rowhammer on AMD Zen DDR4/DDR5 using aggressive row-conflict patterns"},

    {"cve": "CVE-2018-12207", "name": "iTLB Multihit", "class": "meltdown",
     "vendor": "Intel", "arch_filter": "!",
     "severity": "HIGH", "privilege": "unprivileged",
     "description": "Instruction TLB Multihit allows guest VM to crash the host CPU or trigger high translation latency"},
]


def match_cves(uarch: dict, features: dict, dram_info: dict) -> list[dict]:
    """Match detected HW profile against known CVE list."""
    matches = []

    arch_name = uarch.get("microarchitecture", "")
    vendor = uarch.get("vendor", "")

    for cve in CVES:
        score = 0

        # Vendor match
        if cve.get("vendor") and vendor not in cve["vendor"]:
            continue

        # Architecture filter
        arch_filter = cve.get("arch_filter", "")
        if arch_filter and arch_filter != "!":
            parts = [a.strip() for a in arch_filter.split("|") if a.strip()]
            excludes = [p.lstrip("!") for p in parts if p.startswith("!")]
            includes = [p for p in parts if not p.startswith("!")]

            # Check exclusions first
            if excludes and any(e.lower() in arch_name.lower() for e in excludes):
                continue

            # Check inclusions
            if includes and not any(i.lower() in arch_name.lower() for i in includes):
                continue

        # Feature requirement
        feature_req = cve.get("feature")
        if feature_req:
            if not features.get(feature_req, False):
                continue

        match = {
            "cve": cve["cve"],
            "name": cve["name"],
            "class": cve["class"],
            "severity": cve["severity"],
            "privilege": cve["privilege"],
            "description": cve["description"],
            "applicable": True,
            "confidence": "HIGH",
        }

        matches.append(match)

    return matches


def get_vulnerability_report(uarch: dict, features: dict, dram_info: dict) -> dict:
    """Generate complete vulnerability report."""

    cve_matches = match_cves(uarch, features, dram_info)

    return {
        "timestamp": None,  # filled in by reporter
        "system": {
            "microarchitecture": uarch,
            "features": features,
            "memory": dram_info,
        },
        "vulnerabilities": {
            "total": len(cve_matches),
            "critical": len([c for c in cve_matches if c["severity"] == "CRITICAL"]),
            "high": len([c for c in cve_matches if c["severity"] == "HIGH"]),
            "medium": len([c for c in cve_matches if c["severity"] == "MEDIUM"]),
            "low": len([c for c in cve_matches if c["severity"] == "LOW"]),
            "items": cve_matches,
        },
        "rowhammer": {
            "dram_type": dram_info.get("dram_type", "Unknown"),
            "ecc": dram_info.get("ecc", False),
            "rowhammer_vulnerable": dram_info.get("dram_type") in ["DDR3", "DDR4"],
            "rowhammer_method": "Blacksmith frequency-based fuzzing",
            "note": ("DDR3 is trivially vulnerable. DDR4 requires frequency-based "
                     "hammer patterns (Blacksmith/ZenHammer approach). "
                     "DDR5 shows high resilience but is not immune (ZenHammer 2024).")
        },
    }
