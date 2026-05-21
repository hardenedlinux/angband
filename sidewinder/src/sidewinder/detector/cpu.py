"""CPU microarchitecture detection via CPUID and sysfs."""

import os
import re
import platform
from typing import Optional

from sidewinder.utils.system import read_sysfs, read_cpuid_leaf

# CPUID leaf 1: processor info and feature bits
# CPUID leaf 7, subleaf 0: extended features (speculative exec features)

# Microarchitecture profiles derived from CPU Family/Model
# Format: (family, model, stepping_range) -> microarchitecture
# Stepping 0 means matches all steppings.

MICROARCH_PROFILES: list[tuple[tuple, str, str, str]] = [
    # Format: ((family, model, stepping_lo, stepping_hi), arch_name, vendor, generation)

    # Intel
    ((6, 140, 0, 0), "Alder Lake",   "Intel", "12th Gen"),
    ((6, 151, 0, 0), "Raptor Lake",  "Intel", "13th Gen"),
    ((6, 183, 0, 0), "Raptor Lake",  "Intel", "14th Gen"),
    ((6, 186, 0, 0), "Raptor Lake",  "Intel", "14th Gen"),
    ((6, 170, 0, 0), "Meteor Lake",  "Intel", "Core Ultra 100"),
    ((6, 165, 0, 0), "Comet Lake",   "Intel", "10th Gen"),
    ((6, 167, 0, 0), "Rocket Lake",  "Intel", "11th Gen"),
    ((6, 158, 0, 0), "Coffee Lake",  "Intel", "9th Gen"),
    ((6, 142, 0, 0), "Coffee Lake",  "Intel", "8th Gen"),
    ((6, 126, 0, 0), "Kaby Lake",    "Intel", "7th Gen"),
    ((6, 94, 0, 0),  "Skylake",      "Intel", "6th Gen"),
    ((6, 85, 0, 0),  "Skylake-SP",   "Intel", "Xeon Scalable 1st"),
    ((6, 106, 0, 0), "Ice Lake-SP",  "Intel", "Xeon Scalable 3rd"),
    ((6, 143, 0, 0), "Sapphire Rapids-SP", "Intel", "Xeon Scalable 4th"),
    ((6, 173, 0, 0), "Emerald Rapids-SP",  "Intel", "Xeon Scalable 5th"),
    ((6, 60, 0, 0),  "Haswell",      "Intel", "4th Gen"),
    ((6, 69, 0, 0),  "Haswell",      "Intel", "4th Gen"),
    ((6, 70, 0, 0),  "Haswell",      "Intel", "4th Gen"),
    ((6, 61, 0, 0),  "Broadwell",    "Intel", "5th Gen"),
    ((6, 71, 0, 0),  "Broadwell",    "Intel", "5th Gen"),
    ((6, 79, 0, 0),  "Broadwell",    "Intel", "5th Gen"),
    ((6, 87, 0, 0),  "Cannon Lake",  "Intel", "10nm test"),
    ((6, 154, 0, 0), "Alder Lake-N", "Intel", "12th Gen N"),
    ((6, 190, 0, 0), "Emerald Rapids", "Intel", "5th Gen Xeon"),
    ((6, 191, 0, 0), "Lunar Lake",   "Intel", "Core Ultra 200V"),
    ((6, 197, 0, 0), "Arrow Lake",   "Intel", "Core Ultra 200S"),
    ((6, 207, 0, 0), "Panther Lake", "Intel", "Core Ultra 300"),
    ((6, 55, 0, 0),  "Silvermont",   "Intel", "Atom"),
    ((6, 74, 0, 0),  "Silvermont",   "Intel", "Atom"),
    ((6, 76, 0, 0),  "Airmont",      "Intel", "Atom"),
    ((6, 92, 0, 0),  "Goldmont",     "Intel", "Atom"),
    ((6, 122, 0, 0), "Goldmont Plus", "Intel", "Atom"),
    ((6, 134, 0, 0), "Tremont",      "Intel", "Atom"),
    ((6, 156, 0, 0), "Gracemont",    "Intel", "Atom E-core"),

    # AMD
    ((23, 1, 0, 0),  "Zen 1",       "AMD", "Ryzen 1000"),
    ((23, 8, 0, 0),  "Zen+",        "AMD", "Ryzen 2000"),
    ((23, 17, 0, 0), "Zen 1",       "AMD", "Ryzen 1000 (APU)"),
    ((23, 24, 0, 0), "Zen+",        "AMD", "Ryzen 2000 (APU)"),
    ((23, 49, 0, 0), "Zen 2",       "AMD", "Ryzen 3000"),
    ((23, 96, 0, 0), "Zen 2",       "AMD", "Ryzen 4000 (APU)"),
    ((23, 113, 0, 0), "Zen 3",      "AMD", "Ryzen 5000"),
    ((25, 0, 0, 0),  "Zen 2",       "AMD", "EPYC Rome"),
    ((25, 1, 0, 0),  "Zen 3",       "AMD", "EPYC Milan"),
    ((25, 17, 0, 0), "Zen 4",       "AMD", "EPYC Genoa"),
    ((25, 80, 0, 0), "Zen 4",       "AMD", "Ryzen 5000/7000 (Phoenix)"),
    ((25, 2, 0, 0),  "Zen 2",       "AMD", "Threadripper 3000"),
    ((25, 8, 0, 0),  "Zen 3",       "AMD", "Threadripper 5000"),
    # Zen 4: Family 25 Model 64-95, Family 26 Model 0-31
    ((25, 68, 0, 0), "Zen 4",       "AMD", "Ryzen 7000/8000"),
    ((26, 0, 0, 0),  "Zen 4",       "AMD", "Ryzen 7000"),
    ((26, 1, 0, 0),  "Zen 4",       "AMD", "Ryzen 7000"),
    ((26, 32, 0, 0), "Zen 5",       "AMD", "Ryzen 9000"),
    ((26, 36, 0, 0), "Zen 5",       "AMD", "EPYC Turin"),
]


def detect_cpu_vendor() -> str:
    info = read_sysfs("/proc/cpuinfo")
    if "GenuineIntel" in info:
        return "Intel"
    if "AuthenticAMD" in info:
        return "AMD"
    if "ARM" in info or "aarch64" in platform.machine():
        return "ARM"
    return "Unknown"


def detect_microarchitecture() -> Optional[dict]:
    """Identify CPU microarchitecture and return a profile dict."""
    info = read_sysfs("/proc/cpuinfo")
    vendor = detect_cpu_vendor()

    family = model = stepping = None
    fm_match = re.search(r"cpu family\s*:\s*(\d+)", info)
    if fm_match:
        family = int(fm_match.group(1))
    m_match = re.search(r"model\s*:\s*(\d+)", info)
    if m_match:
        model = int(m_match.group(1))
    s_match = re.search(r"stepping\s*:\s*(\d+)", info)
    if s_match:
        stepping = int(s_match.group(1))

    if family is None or model is None:
        return None

    matches = []
    for (f, m, slo, shi), arch, ven, gen in MICROARCH_PROFILES:
        if f != family or m != model:
            continue
        if slo != 0 and stepping is not None and stepping < slo:
            continue
        if shi != 0 and stepping is not None and stepping > shi:
            continue
        matches.append({"family": family, "model": model, "stepping": stepping,
                        "microarchitecture": arch, "vendor": ven, "generation": gen})

    if matches:
        result = matches[0].copy()
        result["vendor"] = vendor
        return result

    return {
        "family": family,
        "model": model,
        "stepping": stepping,
        "microarchitecture": f"{vendor} Family {family} Model {model}",
        "vendor": vendor,
        "generation": "unknown",
    }


def detect_cpu_features() -> dict:
    """Extract CPU feature flags relevant to side-channel vulnerabilities."""
    vendor = detect_cpu_vendor()
    features = {}

    # CPUID leaf 1: basic features
    eax1, ebx1, ecx1, edx1 = read_cpuid_leaf(1)

    # CPUID leaf 7, subleaf 0: extended features (speculative execution)
    eax7, ebx7, ecx7, edx7 = read_cpuid_leaf(7, 0)

    features["vendor"] = vendor
    features["constant_tsc"] = bool(edx7 & (1 << 8)) if vendor == "Intel" else True
    features["invariant_tsc"] = bool(edx7 & (1 << 8)) if vendor == "Intel" else bool(ebx1 & (1 << 4))

    # Intel-specific speculative execution features
    features["tsx"] = bool(ebx7 & (1 << 11))
    features["avx2"] = bool(ebx7 & (1 << 5))
    features["avx512f"] = bool(ebx7 & (1 << 16))
    features["smap"] = bool(ebx7 & (1 << 20))
    features["smep"] = bool(ebx7 & (1 << 7))
    features["smt"] = bool(edx1 & (1 << 28))

    # Detection from sysfs vulnerability directory
    vuln_dir = "/sys/devices/system/cpu/vulnerabilities"
    for vname in os.listdir(vuln_dir) if os.path.isdir(vuln_dir) else []:
        try:
            with open(f"{vuln_dir}/{vname}") as f:
                features[f"mitigation_{vname}"] = f.read().strip()
        except Exception:
            features[f"mitigation_{vname}"] = "unknown"

    # Microcode version
    microcode = read_sysfs("/proc/cpuinfo")
    mc = re.search(r"microcode\s*:\s*0x([0-9a-fA-F]+)", microcode)
    features["microcode_version"] = int(mc.group(1), 16) if mc else 0

    # Cache info
    nproc = len([d for d in os.listdir("/sys/devices/system/cpu")
                 if d.startswith("cpu") and d[3:].isdigit()])
    features["logical_cpus"] = nproc

    return features


def detect_vulnerability_status() -> dict:
    """Comprehensive vulnerability status from /sys + /proc."""
    import os

    result = {}
    vuln_dir = "/sys/devices/system/cpu/vulnerabilities"

    if os.path.isdir(vuln_dir):
        for entry in sorted(os.listdir(vuln_dir)):
            try:
                with open(f"{vuln_dir}/{entry}") as f:
                    result[entry] = f.read().strip()
            except Exception:
                result[entry] = "unreadable"

    # Check /proc/cmdline for kernel boot mitigations
    try:
        with open("/proc/cmdline") as f:
            cmdline = f.read().strip()
        for param in ["mitigations=off", "nospectre_v1", "nospectre_v2",
                       "nopti", "noibrs", "noibpb", "nosmt", "tsx=on", "tsx=off"]:
            result[f"cmdline_{param}"] = param in cmdline
    except Exception:
        pass

    return result
