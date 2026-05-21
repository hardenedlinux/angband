"""sidewinder CLI entry point.

sidewinder - Userland side-channel and Rowhammer vulnerability hunting toolkit.

Usage:
    sidewinder detect [--cpu] [--dram] [--cve CVE-ID] [--json]
    sidewinder probe side-channel|speculative|rowhammer [--time MINUTES]
    sidewinder exploit kaslr|credential-leak|rowhammer [--scenario vm|host]
    sidewinder auto [--scenario vm|host]
    sidewinder report [--format json|markdown]
"""

import os
import sys
import time
from datetime import datetime

import click

from sidewinder import __version__
from sidewinder.report.reporter import generate_full_report, format_report_json, format_report_markdown


def _check_prerequisites() -> tuple[bool, str]:
    """Check prerequisites before running probes or exploits."""
    issues = []

    if sys.platform != "linux":
        issues.append("sidewinder requires Linux (x86_64)")

    if not os.path.exists("/proc/self/pagemap"):
        issues.append("/proc/self/pagemap not available - physical address resolution disabled")

    if os.path.exists("/sys/module/msr"):
        pass  # MSR available, but not required

    # Check if libsidewinder.so can be loaded
    try:
        from sidewinder.primitives.native import get_lib
        get_lib()
    except Exception as e:
        issues.append(f"Cannot load native library: {e}\n  Build with: make -C c_primitives")

    return len(issues) == 0, "\n".join(f"  - {i}" for i in issues)


@click.group()
@click.version_option(__version__, prog_name="sidewinder")
@click.pass_context
def main(ctx):
    """sidewinder - Userland microarchitectural attack toolkit.

    Hunts side-channel and Rowhammer vulnerabilities via userland primitives.
    No kernel modules. No eBPF. Works on x86_64 Linux.
    """
    ctx.ensure_object(dict)
    ctx.obj["scenario"] = "host"


@main.command()
@click.option("--cpu", is_flag=True, help="CPU-only detection")
@click.option("--dram", is_flag=True, help="DRAM-only detection")
@click.option("--cve", default="", help="Check specific CVE status")
@click.option("--json", "json_output", is_flag=True, help="Output as JSON")
@click.option("--output", "-o", default="", help="Write report to file")
@click.pass_context
def detect(ctx, cpu, dram, cve, json_output, output):
    """Detect CPU vulnerabilities and system configuration.

    Runs passive detection: CPUID, /sys, mitigation status, DRAM info.
    No active probing or exploitation.
    """
    from sidewinder.detector.cpu import (
        detect_microarchitecture, detect_cpu_features,
        detect_vulnerability_status,
    )
    from sidewinder.detector.mitigation import check_mitigation_status
    from sidewinder.detector.dram import get_dram_info
    from sidewinder.detector.profile import match_cves

    click.echo(f"[*] sidewinder v{__version__} - Detection Mode")
    click.echo()

    uarch = detect_microarchitecture()
    features = detect_cpu_features()
    _ = detect_vulnerability_status()
    mit = check_mitigation_status()
    dram_info = get_dram_info()

    if not cpu:
        click.echo(f"CPU: {uarch.get('vendor', 'Unknown')} {uarch.get('microarchitecture', 'Unknown')} "
                   f"({uarch.get('generation', 'unknown')})")
        click.echo(f"  Family={uarch.get('family')} Model={uarch.get('model')} Stepping={uarch.get('stepping')}")
        click.echo(f"  Logical CPUs: {features.get('logical_cpus', '?')} "
                   f"SMT={'ON' if features.get('smt') else 'OFF'} "
                   f"TSX={'ON' if features.get('tsx') else 'OFF'}")
        click.echo(f"  Microcode: 0x{features.get('microcode_version', 0):x}")
        click.echo()

    if not dram:
        click.echo(f"DRAM: {dram_info.get('dram_type', 'Unknown')} "
                   f"{dram_info.get('total_size_gb', '?')}GB "
                   f"ECC={'YES' if dram_info.get('ecc') else 'NO'} "
                   f"Channels: {dram_info.get('channels', '?')}")
        click.echo()

    click.echo("Kernel Mitigations:")
    vulns = mit.get("vulnerabilities", {})
    for name, info in sorted(vulns.items()):
        status = info.get("status", "unknown")
        if info.get("vulnerable"):
            click.echo(f"  [VULN] {name}: {status}")
        else:
            click.echo(f"  [ OK ] {name}: {status}")
    click.echo()

    # CVE matching
    cve_matches = match_cves(uarch, features, dram_info)
    if cve:
        matches = [m for m in cve_matches if cve.upper() in m.get("cve", "")]
        if matches:
            m = matches[0]
            click.echo(f"CVE: {m['cve']} ({m['name']})")
            click.echo(f"  Severity: {m['severity']}")
            click.echo(f"  Applicable: {'YES' if m.get('applicable') else 'NO'}")
            click.echo(f"  {m['description']}")
        else:
            click.echo(f"CVE {cve}: Not applicable to this system")
    else:
        severity_colors = {"CRITICAL": "red", "HIGH": "red", "MEDIUM": "yellow", "LOW": "green"}
        critical_high = [m for m in cve_matches if m["severity"] in ("CRITICAL", "HIGH")]
        if critical_high:
            click.echo(f"Applicable CVEs: {len(cve_matches)} total, {len(critical_high)} HIGH/CRITICAL")
            for m in sorted(cve_matches, key=lambda x: (-len(x["severity"]), x["cve"])):
                prefix = "[!!!]" if m["severity"] in ("CRITICAL", "HIGH") else "[ * ]"
                click.echo(f"  {prefix} {m['cve']} {m['name']} ({m['severity']}) - {m['description'][:80]}")
        else:
            click.echo(f"Applicable CVEs: {len(cve_matches)} (no HIGH/CRITICAL)")

    # Report output
    report = generate_full_report({"_scenario": ctx.obj.get("scenario", "host")})
    if json_output:
        click.echo(format_report_json(report))
    if output:
        with open(output, "w") as f:
            if output.endswith(".json"):
                f.write(format_report_json(report))
            else:
                f.write(format_report_markdown(report))
        click.echo(f"\n[+] Report written to {output}")


@main.group()
@click.pass_context
def probe(ctx):
    """Active probing for side-channel and Rowhammer vulnerabilities."""
    ok, issues = _check_prerequisites()
    if not ok:
        click.echo(f"[!] Prerequisites not met:\n{issues}\n")
        sys.exit(1)


@probe.command("side-channel")
@click.pass_context
def probe_side_channel(ctx):
    """Run cache side-channel probes (Flush+Reload, Prime+Probe, calibration)."""
    from sidewinder.probe.cache_side import run_side_channel_probe

    click.echo("[*] Probing cache side channels...")
    click.echo()

    results = run_side_channel_probe()

    calib = results.get("calibration", {})
    click.echo(f"Calibration:")
    click.echo(f"  Hit avg:   {calib.get('hit_avg', 0):.1f} cycles")
    click.echo(f"  Miss avg:  {calib.get('miss_avg', 0):.1f} cycles")
    click.echo(f"  Threshold: {calib.get('threshold', 0):.1f} cycles")
    click.echo(f"  Quality:   {calib.get('quality', 'unknown')}")
    click.echo()

    fr = results.get("flush_reload", {})
    if fr:
        click.echo(f"Flush+Reload ({fr.get('library', 'N/A')}):")
        click.echo(f"  Hit rate:  {fr.get('hit_rate_pct', 0):.1f}%")
        click.echo(f"  Viable:    {'YES' if fr.get('side_channel_viable') else 'NO'}")

    pp = results.get("prime_probe", {})
    click.echo(f"\nPrime+Probe ({pp.get('buffer_size_kb', 0)}KB buffer):")
    click.echo(f"  Avg hits:  {pp.get('avg_primed_hits', 0):.1f}")
    click.echo(f"  Viable:    {'YES' if pp.get('side_channel_viable') else 'NO'}")


@probe.command("speculative")
@click.pass_context
def probe_speculative(ctx):
    """Test speculative execution vulnerabilities (Spectre v1, Meltdown, etc.)."""
    from sidewinder.probe.speculative import run_speculative_probes

    click.echo("[*] Testing speculative execution...")
    click.echo()

    results = run_speculative_probes()
    probes = results.get("speculative_probes", {})

    for name, data in probes.items():
        viable = data.get("viable", False)
        status = "VULNERABLE" if viable else "OK"
        click.echo(f"  [{status}] {data.get('attack', name)} ({data.get('cve', '')})")
        click.echo(f"         {data.get('note', '')}")


@probe.command("rowhammer")
@click.option("--time", "timeout", default=60, help="Fuzzing duration in minutes")
@click.option("--region", default=256, help="Memory region size in MB")
@click.pass_context
def probe_rowhammer(ctx, timeout, region):
    """Run Rowhammer fuzzer with frequency-based hammer patterns."""
    from sidewinder.probe.rowhammer import run_rowhammer_probe

    click.echo(f"[*] Rowhammer fuzzer - {timeout} minute(s) limit, {region}MB region")
    click.echo("[*] Using Blacksmith-style frequency-based patterns")
    click.echo("[*] Press Ctrl+C to stop early")
    click.echo()

    try:
        result = run_rowhammer_probe(timeout_minutes=timeout, region_mb=region)
    except KeyboardInterrupt:
        click.echo("\n[!] Interrupted")
        return

    if result["success"]:
        click.echo(f"\n[+] BIT FLIPS FOUND: {result['flips_found']}")
        for f in result.get("flips", []):
            click.echo(f"    Addr: {f['address']}  Bit: {f['bit']}  "
                       f"From: 0x{f['from']:02x}  To: 0x{f['to']:02x}")
    else:
        click.echo(f"\n[-] No bit flips found ({result.get('duration_sec', 0):.0f}s)")
        if result.get("error"):
            click.echo(f"    {result['error']}")
    click.echo(f"\n    Total activations: {result.get('total_activations', 0)}")


@probe.command("hertzbleed")
@click.option("--samples", default=1000, help="Number of timing samples")
@click.pass_context
def probe_hertzbleed(ctx, samples):
    """Test Hertzbleed DVFS timing side-channel (CVE-2022-23823)."""
    from sidewinder.probe.hertzbleed import run_hertzbleed_probe

    click.echo("[*] Hertzbleed probe - DVFS timing side-channel")
    click.echo("[*] Testing if data-dependent power draw leaks through frequency scaling")
    click.echo()

    result = run_hertzbleed_probe(samples=samples)

    if result["vulnerable"]:
        click.echo(f"[VULNERABLE] Hertzbleed detected!")
        click.echo(f"    Timing delta: {result['timing_delta']} cycles")
        click.echo(f"    Leak indicators: {result['leak_indicators']}")
        click.echo(f"    Note: {result['note']}")
    else:
        click.echo(f"[NOT VULN] Hertzbleed not detected")
        click.echo(f"    Timing delta: {result['timing_delta']} cycles")
        click.echo(f"    Note: {result['note']}")


@probe.command("zenhammer")
@click.option("--time", "timeout", default=30, help="Fuzzing duration in minutes")
@click.option("--region", default=256, help="Memory region size in MB")
@click.pass_context
def probe_zenhammer(ctx, timeout, region):
    """Run ZenHammer - AMD Zen DDR5 Rowhammer (2024)."""
    from sidewinder.probe.zenhammer import run_zenhammer_probe

    click.echo(f"[*] ZenHammer - AMD Zen DDR5 Rowhammer")
    click.echo(f"[*] Duration: {timeout} minute(s), Region: {region}MB")
    click.echo("[*] Press Ctrl+C to stop early")
    click.echo()

    try:
        result = run_zenhammer_probe(timeout_minutes=timeout, region_mb=region)
    except KeyboardInterrupt:
        click.echo("\n[!] Interrupted")
        return

    if result["success"]:
        click.echo(f"\n[+] BIT FLIPS FOUND: {result['flips_found']}")
        for f in result.get("flips", []):
            click.echo(f"    Addr: {f['address']}  Bit: {f['bit']}  "
                       f"From: 0x{f['from']:02x}  To: 0x{f['to']:02x}")
    else:
        click.echo(f"\n[-] No bit flips found ({result.get('duration_sec', 0):.0f}s)")
        if result.get("error"):
            click.echo(f"    {result['error']}")
    click.echo(f"\n    Total activations: {result.get('total_activations', 0)}")


@main.group()
@click.pass_context
def exploit(ctx):
    """Run exploitation modules (info leak or privilege escalation)."""
    ok, issues = _check_prerequisites()
    if not ok:
        click.echo(f"[!] Prerequisites not met:\n{issues}\n")
        sys.exit(1)


@exploit.command("kaslr")
@click.pass_context
def exploit_kaslr(ctx):
    """Bypass KASLR via kallsyms or side-channel."""
    from sidewinder.exploit.kaslr import run_kaslr_bypass

    click.echo("[*] KASLR bypass...")
    result = run_kaslr_bypass()

    if result.get("success"):
        click.echo(f"[+] Method: {result.get('method')}")
        click.echo(f"    Kernel base:    {hex(result['kernel_base'])}")
        click.echo(f"    KASLR slide:    {hex(result.get('kaslr_slide', 0))}")
        syms = result.get("key_symbols", {})
        if syms:
            click.echo(f"    Key symbols:")
            for sym, addr in syms.items():
                if addr:
                    click.echo(f"      {sym}: {hex(addr)}")
    else:
        click.echo(f"[-] Failed: {result.get('error')}")


@exploit.command("credential-leak")
@click.pass_context
def exploit_credential_leak(ctx):
    """Leak credentials via Meltdown/Zenbleed/Downfall (host safe)."""
    from sidewinder.exploit.cred_leak import run_credential_leak

    click.echo("[*] Attempting credential leak (info-leak only)...")
    result = run_credential_leak()

    for method in result.get("methods", []):
        status = "OK" if method["success"] else "FAIL"
        click.echo(f"  [{status}] {method['method']}")
        if method.get("error"):
            click.echo(f"         {method['error']}")
        if method.get("bytes_leaked"):
            click.echo(f"         Leaked {method['bytes_leaked']} bytes "
                       f"at {method.get('leak_rate_bps', 0):.1f} B/s")


@exploit.command("spy-leak")
@click.option("--target", default="/etc/shadow", help="Target file to leak from victim")
@click.pass_context
def exploit_spy_leak(ctx, target):
    """Flush+Reload spy: leak victim file contents via cache side-channel."""
    from sidewinder.exploit.verify import spy_leak_demo

    click.echo(f"[*] Flush+Reload spy attack targeting: {target}")
    click.echo("[*] Forks victim that reads file, attacker (parent) recovers via cache")
    click.echo()

    result = spy_leak_demo()

    if result["success"]:
        click.echo(f"[+] Successfully leaked {result['bytes_recovered']} bytes")
    else:
        click.echo(f"[-] Failed: {result['error']}")


@exploit.command("verify-escalation")
@click.option("--scenario", default="vm", type=click.Choice(["vm", "host"]),
              help="Scenario: vm for full escalation, host for detection only")
@click.pass_context
def exploit_verify_escalation(ctx, scenario):
    """Full Rowhammer escalation chain verification (VM only)."""
    from sidewinder.exploit.verify import rowhammer_ptescan_and_escalate

    if scenario == "host":
        click.echo("[!] Escalation verification blocked on host. Use --scenario vm.")
        return

    click.echo("[*] Rowhammer Escalation Chain Verification")
    click.echo("[!] VM ONLY — this will attempt kernel memory writes.")
    click.echo()
    click.confirm("Continue with full escalation in VM?", abort=True)

    result = rowhammer_ptescan_and_escalate(scenario)
    click.echo()
    click.echo(f"[{'OK' if result.success else 'FAIL'}] Escalation: {result.method or 'PTE flip + modprobe_path'}")
    click.echo(f"  Kernel base:    0x{result.kernel_base:x}")
    click.echo(f"  PTEs found:     {result.ptes_found}")
    click.echo(f"  Flip achieved:  {'YES' if result.flip_achieved else 'NO'}")
    click.echo(f"  Modprobe overwritten: {'YES' if result.modprobe_overwritten else 'NO'}")
    click.echo(f"  Root confirmed: {'YES' if result.root_confirmed else 'NO'}")
    if result.error:
        click.echo(f"  Error: {result.error}")


@exploit.command("rowhammer-escalation")
@click.option("--scenario", default="vm", type=click.Choice(["vm", "host"]),
              help="Scenario: vm allows writes, host is read-only")
@click.pass_context
def exploit_rowhammer(ctx, scenario):
    """Rowhammer privilege escalation (VM only)."""
    from sidewinder.exploit.pte_flip import run_escalation

    if scenario == "host":
        click.echo("[!] Rowhammer escalation blocked on host (--scenario host).")
        click.echo("    Use --scenario vm for full exploitation in a VM.")
        return

    click.echo("[*] Rowhammer privilege escalation (VM mode)...")
    click.echo("[!] WARNING: This writes to kernel memory via DRAM bit flips!")
    click.echo("[!] Only safe in a disposable VM/QEMU guest.")
    click.echo()
    click.confirm("Continue?", abort=True)

    result = run_escalation(scenario)

    for method in result.get("methods", []):
        status = "ESCALATED" if method["success"] else "FAIL"
        click.echo(f"  [{status}] {method['method']}")
        if method.get("error"):
            click.echo(f"         {method['error']}")


@exploit.command("vmscape")
@click.option("--timeout", default=60, help="Timeout in seconds")
@click.option("--exfiltrate", is_flag=True, help="Attempt actual data exfiltration")
@click.option("--bytes", default=64, help="Number of bytes to attempt to exfiltrate")
@click.pass_context
def exploit_vmscape(ctx, timeout, exfiltrate, bytes):
    """VM-to-Host leak via VMScape, L1TF, and MDS (host-safe info leak).

    VMScape (CVE-2025-40300): Spectre-BTI across VM boundaries.
    L1TF/Foreshadow (CVE-2018-3615/3620/3646): L1 terminal fault.
    MDS/ZombieLoad (CVE-2018-12126/12127/12130): Microarchitectural data sampling.

    These attacks allow a VM guest to leak data from the host hypervisor
    or other VMs. All methods are read-only (info leak only).

    Use --exfiltrate to attempt actual data exfiltration.
    """
    from sidewinder.exploit.vmscape import run_vm_to_host_probes, exfiltrate_vmscape

    if exfiltrate:
        click.echo(f"[*] VMScape Data Exfiltration (target: {bytes} bytes)")
        click.echo("[*] This uses BHB poisoning to attempt data exfiltration")
        click.echo()

        result = exfiltrate_vmscape(timeout_sec=timeout, target_bytes=bytes)

        if result.success:
            click.echo(f"  [LEAKED] VMSCAPE Data Exfiltration")
            click.echo(f"         Exfiltrated: {result.bytes_leaked} bytes")
            click.echo(f"         Rate: {result.leak_rate_bps:.1f} B/s")
            if result.data_sample:
                sample = result.data_sample[:64]
                printable = bytearray(b if 32 <= b < 127 else ord('.') for b in sample)
                click.echo(f"         Sample: {printable}")
        else:
            click.echo(f"  [FAILED] VMScape exfiltration: {result.error}")
        return

    click.echo("[*] VM-to-Host Leak Probes (VMScape, L1TF, MDS)")
    click.echo("[*] These attacks allow a VM guest to leak host memory")
    click.echo("[*] All probes are read-only (info leak only)")
    click.echo()

    result = run_vm_to_host_probes(timeout_sec=timeout)

    for method in result.get("methods", []):
        status = "LEAKED" if method["success"] else "NOT VULN"
        click.echo(f"  [{status}] {method['method'].upper()} ({method['cve']})")
        if method["success"]:
            leak_val = method.get("bytes_leaked") or method.get("leak_indicators", 0)
            click.echo(f"         Leaked: {leak_val} bytes/indicators")
            click.echo(f"         Rate: {method.get('leak_rate_bps', 0):.1f} B/s")
        else:
            click.echo(f"         {method['error']}")
        if method.get("note"):
            click.echo(f"         {method['note']}")


@main.command("auto")
@click.option("--scenario", default="host", type=click.Choice(["vm", "host"]),
              help="Scenario: vm for full exploit, host for detect+probe+info-leak only")
@click.option("--timeout", default=600, help="Total timeout in seconds")
@click.option("--output", "-o", default="", help="Write report to file")
@click.pass_context
def auto(ctx, scenario, timeout, output):
    """Full automated scan: detect -> probe -> exploit (based on scenario)."""
    ok, issues = _check_prerequisites()
    if not ok:
        click.echo(f"[!] Prerequisites not met:\n{issues}\n")
        click.echo("Proceeding with detection-only scan...")
        click.echo()

    click.echo(f"[*] sidewinder AUTO mode (scenario: {scenario}, timeout: {timeout}s)")
    click.echo()

    scan_results = {"_scenario": scenario}
    deadline = time.time() + timeout

    try:
        # Phase 1: Detection
        from sidewinder.detector.cpu import detect_microarchitecture, detect_cpu_features
        from sidewinder.detector.mitigation import check_mitigation_status
        from sidewinder.detector.dram import get_dram_info

        click.echo("[Phase 1/4] System detection...")
        uarch = detect_microarchitecture()
        features = detect_cpu_features()
        mit = check_mitigation_status()
        dram_info = get_dram_info()

        vuln_count = sum(1 for v in mit.get("vulnerabilities", {}).values() if v.get("vulnerable"))
        click.echo(f"  CPU: {uarch.get('vendor', '?')} {uarch.get('microarchitecture', '?')}")
        click.echo(f"  DRAM: {dram_info.get('dram_type', '?')} {dram_info.get('total_size_gb', '?')}GB")
        click.echo(f"  Vulnerable mitigations: {vuln_count}")
        scan_results["detection"] = {"microarchitecture": uarch, "mitigation_vulns": vuln_count}

        if time.time() > deadline:
            click.echo("[!] Timeout during detection")

        # Phase 2: Side-channel probe
        click.echo("\n[Phase 2/4] Cache side-channel and vulnerability probing...")
        try:
            from sidewinder.probe.cache_side import run_side_channel_probe
            sc_results = run_side_channel_probe()
            scan_results["side_channel"] = {
                "calibration_quality": sc_results.get("calibration", {}).get("quality", "unknown"),
                "flush_reload_viable": sc_results.get("flush_reload", {}).get("side_channel_viable", False),
                "prime_probe_viable": sc_results.get("prime_probe", {}).get("side_channel_viable", False),
            }
        except Exception as e:
            click.echo(f"  [!] Side-channel probe failed: {e}")
            scan_results["side_channel"] = {"error": str(e)}

        # Run Hertzbleed probe
        click.echo("  Running Hertzbleed probe...")
        try:
            from sidewinder.probe.hertzbleed import run_hertzbleed_probe
            hb_result = run_hertzbleed_probe(samples=100)
            scan_results["hertzbleed"] = {
                "vulnerable": hb_result.get("vulnerable", False),
                "timing_delta": hb_result.get("timing_delta", 0),
                "leak_indicators": hb_result.get("leak_indicators", 0),
            }
            click.echo(f"    Hertzbleed: {'VULNERABLE' if hb_result.get('vulnerable') else 'NOT VULNERABLE'} ({hb_result.get('timing_delta', 0)} cycles delta)")
        except Exception as e:
            click.echo(f"    [!] Hertzbleed probe failed: {e}")
            scan_results["hertzbleed"] = {"error": str(e)}

        # Run ZenHammer probe if AMD
        if uarch.get("vendor") == "AMD":
            click.echo("  Running ZenHammer probe (1 minute limit)...")
            try:
                from sidewinder.probe.zenhammer import run_zenhammer_probe
                zh_result = run_zenhammer_probe(timeout_minutes=1, region_mb=64)
                scan_results["zenhammer"] = {
                    "success": zh_result.get("success", False),
                    "flips_found": zh_result.get("flips_found", 0),
                }
                click.echo(f"    ZenHammer flips found: {zh_result.get('flips_found', 0)}")
            except Exception as e:
                click.echo(f"    [!] ZenHammer probe failed: {e}")
                scan_results["zenhammer"] = {"error": str(e)}

        if time.time() > deadline:
            click.echo("[!] Timeout during side-channel probe")

        # Phase 3: KASLR bypass
        click.echo("\n[Phase 3/4] KASLR bypass...")
        try:
            from sidewinder.exploit.kaslr import run_kaslr_bypass
            kaslr_result = run_kaslr_bypass()
            scan_results["kaslr"] = {
                "success": kaslr_result.get("success", False),
                "method": kaslr_result.get("method", "unknown"),
                "kernel_base": hex(kaslr_result.get("kernel_base", 0)) if kaslr_result.get("kernel_base") else None,
            }
            if kaslr_result.get("success"):
                click.echo(f"  Kernel base: {hex(kaslr_result.get('kernel_base', 0))}")
            else:
                click.echo(f"  Failed: {kaslr_result.get('error', 'unknown')[:80]}")
        except Exception as e:
            click.echo(f"  [!] KASLR bypass failed: {e}")
            scan_results["kaslr"] = {"error": str(e)}

        # Phase 4: Scenario-specific actions
        click.echo(f"\n[Phase 4/4] Scenario actions ({scenario})...")
        if scenario == "vm" and time.time() < deadline:
            click.echo("  VM mode: attempting credential leak + rowhammer escalation...")
            try:
                from sidewinder.exploit.cred_leak import run_credential_leak
                cred_result = run_credential_leak()
                scan_results["credential_leak"] = {
                    "success": cred_result.get("success", False),
                }
            except Exception as e:
                scan_results["credential_leak"] = {"error": str(e)}

            try:
                from sidewinder.exploit.pte_flip import run_escalation
                esc_result = run_escalation(scenario)
                scan_results["escalation"] = {
                    "success": esc_result.get("success", False),
                }
            except Exception as e:
                scan_results["escalation"] = {"error": str(e)}
        else:
            click.echo("  Host mode: credential leak only (no writes)...")
            try:
                from sidewinder.exploit.cred_leak import run_credential_leak
                cred_result = run_credential_leak()
                scan_results["credential_leak"] = {
                    "success": cred_result.get("success", False),
                }
            except Exception as e:
                scan_results["credential_leak"] = {"error": str(e)}

    except KeyboardInterrupt:
        click.echo("\n[!] Interrupted. Generating partial report...")

    # Generate report
    click.echo("\n[*] Generating report...")
    report = generate_full_report(scan_results)

    json_report = format_report_json(report)
    md_report = format_report_markdown(report)

    if output:
        with open(output, "w") as f:
            if output.endswith(".json"):
                f.write(json_report)
            elif output.endswith(".md"):
                f.write(md_report)
            else:
                f.write(json_report)
        click.echo(f"[+] Report written to {output}")
    else:
        # Write to default location
        report_dir = "/tmp/sidewinder_reports"
        os.makedirs(report_dir, exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        json_path = f"{report_dir}/report_{ts}.json"
        md_path = f"{report_dir}/report_{ts}.md"
        with open(json_path, "w") as f:
            f.write(json_report)
        with open(md_path, "w") as f:
            f.write(md_report)
        click.echo(f"[+] Reports written to:")
        click.echo(f"    {json_path}")
        click.echo(f"    {md_path}")


@main.command("report")
@click.option("--format", "fmt", default="markdown", type=click.Choice(["json", "markdown"]),
              help="Output format")
@click.option("--output", "-o", default="", help="Write report to file")
@click.argument("input_file", required=False)
@click.pass_context
def report(ctx, fmt, output, input_file):
    """Generate vulnerability report from scan data or live system."""
    if input_file:
        import json as _json
        with open(input_file) as f:
            report = _json.load(f)
    else:
        report = generate_full_report({"_scenario": ctx.obj.get("scenario", "host")})

    if fmt == "json":
        content = format_report_json(report)
    else:
        content = format_report_markdown(report)

    if output:
        with open(output, "w") as f:
            f.write(content)
        click.echo(f"[+] Report written to {output}")
    else:
        click.echo(content)


if __name__ == "__main__":
    main()
