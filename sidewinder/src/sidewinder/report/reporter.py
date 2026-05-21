"""Structured vulnerability report generation (JSON/Markdown)."""

import json
import time
from datetime import datetime
from typing import Any

from sidewinder.detector.cpu import detect_microarchitecture, detect_cpu_features, detect_vulnerability_status
from sidewinder.detector.mitigation import check_mitigation_status
from sidewinder.detector.dram import get_dram_info
from sidewinder.detector.profile import get_vulnerability_report


def generate_full_report(scan_results: dict | None = None) -> dict:
    """Generate comprehensive vulnerability report."""
    now = datetime.utcnow().isoformat() + "Z"

    uarch = detect_microarchitecture() or {}
    features = detect_cpu_features()
    vuln_status = detect_vulnerability_status()
    mit_status = check_mitigation_status()
    dram_info = get_dram_info()
    profile = get_vulnerability_report(uarch, features, dram_info)

    report = {
        "meta": {
            "tool": "sidewinder",
            "version": "0.1.0",
            "timestamp": now,
            "scenario": scan_results.get("_scenario", "unknown") if scan_results else "unknown",
        },
        "system": {
            "microarchitecture": uarch,
            "features": features,
            "memory": dram_info,
        },
        "mitigation_status": mit_status,
        "vulnerability_profile": profile,
    }

    if scan_results:
        report["scan_results"] = {
            k: v for k, v in scan_results.items() if not k.startswith("_")
        }

    return report


def format_report_json(report: dict, indent: int = 2) -> str:
    """Format report as JSON string."""
    class _Encoder(json.JSONEncoder):
        def default(self, obj):
            if isinstance(obj, bytes):
                return obj.hex()
            if isinstance(obj, set):
                return list(obj)
            return super().default(obj)

    return json.dumps(report, indent=indent, cls=_Encoder, default=str)


def format_report_markdown(report: dict) -> str:
    """Format report as Markdown string."""
    lines = []
    meta = report.get("meta", {})
    sys_info = report.get("system", {})
    uarch = sys_info.get("microarchitecture", {})
    features = sys_info.get("features", {})
    memory = sys_info.get("memory", {})
    mit = report.get("mitigation_status", {})
    profile = report.get("vulnerability_profile", {})

    lines.append("# sidewinder Vulnerability Report")
    lines.append(f"**Generated**: {meta.get('timestamp', 'unknown')}")
    lines.append(f"**Tool Version**: {meta.get('version', '0.1.0')}")
    lines.append(f"**Scenario**: {meta.get('scenario', 'unknown')}")
    lines.append("")

    lines.append("## System Information")
    lines.append(f"- **CPU**: {uarch.get('vendor', 'Unknown')} {uarch.get('microarchitecture', 'Unknown')} ({uarch.get('generation', 'unknown')})")
    lines.append(f"- **Family/Model/Stepping**: {uarch.get('family', '?')}/{uarch.get('model', '?')}/{uarch.get('stepping', '?')}")
    lines.append(f"- **Logical CPUs**: {features.get('logical_cpus', '?')}")
    lines.append(f"- **SMT**: {'Yes' if features.get('smt') else 'No'}")
    lines.append(f"- **AVX2**: {'Yes' if features.get('avx2') else 'No'}")
    lines.append(f"- **TSX**: {'Yes' if features.get('tsx') else 'No'}")
    lines.append(f"- **DRAM**: {memory.get('dram_type', 'Unknown')} ({memory.get('total_size_gb', '?')} GB)")
    lines.append(f"- **ECC**: {'Yes' if memory.get('ecc') else 'No'}")
    lines.append("")

    lines.append("## Kernel Mitigations")
    mit_vulns = mit.get("vulnerabilities", {})
    for name, info in sorted(mit_vulns.items()):
        status = "VULNERABLE" if info.get("vulnerable") else "OK"
        emoji = ":red_circle:" if info.get("vulnerable") else ":green_circle:"
        lines.append(f"- {emoji} **{name}**: {status}")
    lines.append("")

    vulns = profile.get("vulnerabilities", {})
    lines.append(f"## Vulnerability Assessment")
    lines.append(f"- **Total applicable CVEs**: {vulns.get('total', 0)}")
    lines.append(f"- **Critical**: {vulns.get('critical', 0)}")
    lines.append(f"- **High**: {vulns.get('high', 0)}")
    lines.append(f"- **Medium**: {vulns.get('medium', 0)}")
    lines.append(f"- **Low**: {vulns.get('low', 0)}")
    lines.append("")

    if vulns.get("items"):
        lines.append("| CVE | Name | Severity | Class |")
        lines.append("|-----|------|----------|-------|")
        for item in vulns["items"]:
            lines.append(f"| {item['cve']} | {item['name']} | {item['severity']} | {item['class']} |")
        lines.append("")

    rh = profile.get("rowhammer", {})
    lines.append("## Rowhammer Assessment")
    lines.append(f"- **DRAM Type**: {rh.get('dram_type', 'Unknown')}")
    lines.append(f"- **ECC**: {'Yes' if rh.get('ecc') else 'No'}")
    lines.append(f"- **Vulnerable**: {'Yes' if rh.get('rowhammer_vulnerable') else 'No'}")
    lines.append(f"- **Method**: {rh.get('rowhammer_method', 'N/A')}")
    lines.append(f"- **Note**: {rh.get('note', '')}")
    lines.append("")

    # Include scan results if any
    scan = report.get("scan_results")
    if scan:
        lines.append("## Active Probe Results")
        lines.append("```json")
        lines.append(json.dumps(scan, indent=2, default=str))
        lines.append("```")
        lines.append("")

    return "\n".join(lines)
