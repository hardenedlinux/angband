from pathlib import Path
import subprocess

import click
import yaml

from angband.core.engine import StageEngine
from angband.generators.poc_gen import PocGenerator
from angband.runtime import (
    default_binary_path,
    default_config_path,
    default_source_path,
    ensure_runtime_dirs,
    workspace_root,
    ssh_dir,
)


def _config_path(target: str) -> Path:
    return workspace_root() / "configs" / f"{target}.yaml"


def _default_target_config(target: str) -> dict:
    target_config_path = _config_path(target)
    if target_config_path.exists():
        with open(target_config_path, "r", encoding="utf-8") as handle:
            return yaml.safe_load(handle) or {}
    return {
        "name": target,
        "stages": {
            "groom": {"method": "simulation_only"},
            "trigger": {"bug_type": "vuln_drill_demo"},
            "leak": {"method": "simulation_only"},
            "primitive": {"method": "simulation_only"},
            "escalate": {"method": "simulation_only"},
            "cleanup": {"method": "simulation_only"},
        },
        "recommended_primitive": "simulation_only",
    }


def _init_payload(cve_or_commit: str, target: str) -> dict:
    target_data = _default_target_config(target)
    stage_defaults = target_data.get("stages", {})
    is_demo = cve_or_commit.lower() == "demo"
    reference_id = None if is_demo else cve_or_commit
    exploit_name = "demo-vuln-drill" if is_demo else cve_or_commit
    demo_profile = "vuln_drill" if is_demo else "cve_reference"
    kernel_target = "vuln_drill" if is_demo else "none"
    scenario = (
        "Safe walkthrough against the synthetic vuln_drill kernel module"
        if is_demo
        else "Safe CVE-labeled walkthrough with metadata only and no synthetic kernel module"
    )

    return {
        "exploit_name": exploit_name,
        "reference_id": reference_id,
        "mode": "demo",
        "demo_profile": demo_profile,
        "kernel_target": kernel_target,
        "scenario": scenario,
        "target": target,
        "recommended_primitive": target_data.get("recommended_primitive", "simulation_only"),
        "stages": {
            "prep": stage_defaults.get("prep", {"method": "environment_checks"}),
            "groom": stage_defaults.get("groom", {"method": "simulation_only"}),
            "trigger": stage_defaults.get("trigger", {"bug_type": "vuln_drill_demo"}),
            "leak": stage_defaults.get("leak", {"method": "simulation_only"}),
            "primitive": stage_defaults.get("primitive", {"method": "simulation_only"}),
            "escalate": stage_defaults.get("escalate", {"method": "simulation_only"}),
            "cleanup": stage_defaults.get("cleanup", {"method": "simulation_only"}),
        },
        "symbol_offsets": target_data.get("symbol_offsets", {}),
    }


@click.group()
@click.version_option("0.1.0")
def main():
    """Angband - Automated kernel exploit generation framework."""


@main.command()
@click.argument("cve_or_commit")
@click.option("--target", default="ubuntu-24.04-x86_64", help="Target config")
def init(cve_or_commit: str, target: str):
    """Initialize a scenario from a CVE, commit hash, or 'demo'."""
    ensure_runtime_dirs()
    config_path = default_config_path()

    is_demo = cve_or_commit.lower() == "demo"

    if is_demo:
        payload = _init_payload(cve_or_commit, target)
        with open(config_path, "w", encoding="utf-8") as handle:
            yaml.safe_dump(payload, handle, sort_keys=False)
        click.echo(f"[*] Initialized demo walkthrough")
        click.echo(f"[*] Target distribution: {target}")
        click.echo(f"[+] Created {config_path}")
        click.echo("[*] Next step: 'angband generate' or 'angband pipeline'")
    else:
        # CVE or commit hash: attempt real analysis
        click.echo(f"[*] Analyzing {cve_or_commit}...")

        try:
            from angband.analysis.vuln_analyzer import VulnAnalyzer

            analyzer = VulnAnalyzer()

            if cve_or_commit.upper().startswith("CVE-"):
                plan = analyzer.analyze_cve(cve_or_commit.upper())
            else:
                plan = analyzer.analyze_commit(cve_or_commit)

            config = plan.to_yaml_config()
            config["target"] = target

            # Merge target-specific data
            target_data = _default_target_config(target)
            config["mitigations"] = target_data.get("mitigations", {})

            with open(config_path, "w", encoding="utf-8") as handle:
                yaml.safe_dump(config, handle, sort_keys=False)

            click.echo(f"[+] Bug class: {plan.bug_class.value}")
            click.echo(f"[+] Subsystem: {plan.subsystem.value}")
            click.echo(f"[+] Confidence: {plan.confidence}")
            click.echo(f"[+] Escalation path: {plan.escalation_path.value}")
            if plan.affected_slab_cache:
                click.echo(f"[+] Target slab cache: {plan.affected_slab_cache}")
            click.echo(f"[+] Created {config_path}")
            click.echo("[*] Next step: 'angband generate' to produce exploit code")

        except Exception as exc:
            # Fall back to metadata-only mode
            click.echo(f"[!] Analysis failed ({exc}), falling back to metadata mode")
            payload = _init_payload(cve_or_commit, target)
            with open(config_path, "w", encoding="utf-8") as handle:
                yaml.safe_dump(payload, handle, sort_keys=False)
            click.echo(f"[+] Created {config_path} (metadata-only)")


@main.command(name="build-env")
def build_env():
    """Describe how to prepare the QEMU environment."""
    config = {}
    config_path = default_config_path()
    if config_path.exists():
        with open(config_path, "r", encoding="utf-8") as handle:
            config = yaml.safe_load(handle) or {}

    target = config.get("target", "ubuntu-24.04-x86_64")
    click.echo("[*] Setting up target environment...")
    click.echo(f"[*] Target: {target}")
    click.echo("[*] Run 'harness/setup.sh' once, then 'harness/launch.sh' to boot the VM")
    click.echo(f"[*] Runtime artifacts are stored under {default_config_path().parents[1]}")


@main.command()
@click.option("--output", default=None, help="Output C file")
def generate(output: str):
    """Generate exploit payload (demo or real based on mode in config)."""
    ensure_runtime_dirs()
    config_file = default_config_path()
    if not config_file.exists():
        click.echo("[!] exploit.yaml not found. Run 'angband init <cve>' first.")
        return

    with open(config_file, "r", encoding="utf-8") as handle:
        config = yaml.safe_load(handle) or {}

    output_path = default_source_path() if output is None else default_source_path().parent / output
    binary_path = default_binary_path()
    mode = config.get("mode", "demo")

    click.echo(f"[*] Mode: {mode}")
    click.echo(f"[*] Generating C code from {config.get('exploit_name')}...")

    generator = PocGenerator(workspace_root() / "templates")
    generator.generate(config, str(output_path))

    click.echo(f"[+] Payload generated: {output_path}")
    click.echo("[*] Compiling...")

    # Link primitives when in exploit mode
    compile_cmd = ["gcc", "-Wall", "-Wextra", "-static", "-o", str(binary_path), str(output_path)]

    result = subprocess.run(compile_cmd, capture_output=True, text=True)
    if result.returncode == 0:
        click.echo(f"[+] Successfully compiled '{binary_path}'")
    else:
        click.echo(f"[!] Compilation failed:\n{result.stderr}")

    if mode == "demo":
        click.echo("[*] Demo mode: walkthrough against vuln_drill target")
    else:
        click.echo(f"[*] Exploit mode: {config.get('escalation_path', 'unknown')} escalation")
    click.echo("[!] This binary must ONLY run inside the QEMU guest")


@main.command()
@click.argument("stage")
@click.option("--config", default=None)
def run_stage(stage: str, config: str):
    """Run a single stage."""
    config_path = str(default_config_path() if config is None else config)
    engine = StageEngine(config_path)
    success = engine.run_stage(stage)
    click.echo(f"Stage {stage} completed: {'SUCCESS' if success else 'FAILED'}")


@main.command()
@click.option("--config", default=None)
def pipeline(config: str):
    """Run the full exploit pipeline."""
    config_path = str(default_config_path() if config is None else config)
    engine = StageEngine(config_path)
    success = engine.run_pipeline()
    click.echo(f"Full pipeline completed: {'SUCCESS' if success else 'FAILED'}")


@main.command()
@click.option("--port", default=2222, help="SSH port")
def recon(port: int):
    """Fingerprint the QEMU guest kernel environment."""
    key_path = ssh_dir() / "id_ed25519"
    if not key_path.exists():
        click.echo("[!] SSH key not found. Run 'harness/setup.sh' first.")
        return

    click.echo("[*] Probing QEMU guest...")

    from angband.recon.fingerprint import TargetProbe

    probe = TargetProbe(ssh_key=key_path, port=port)
    fp = probe.probe()

    click.echo(f"[+] Kernel: {fp.kernel_release}")
    click.echo(f"[+] Arch: {fp.arch}")
    click.echo(f"[+] Slab allocator: {fp.slab_allocator}")
    click.echo(f"[+] KASLR: {fp.kaslr}")
    click.echo(f"[+] SMEP: {fp.smep} | SMAP: {fp.smap}")
    click.echo(f"[+] KPTI: {fp.kpti}")
    click.echo(f"[+] kptr_restrict: {fp.kptr_restrict}")
    click.echo(f"[+] kallsyms readable: {fp.kallsyms_readable}")
    click.echo(f"[+] SELinux: {fp.selinux} | AppArmor: {fp.apparmor}")
    if fp.slab_caches:
        click.echo(f"[+] Slab caches found: {len(fp.slab_caches)}")
    if fp.loaded_modules:
        click.echo(f"[+] Loaded modules: {len(fp.loaded_modules)}")

    # Save fingerprint to runtime dir
    fp_path = default_config_path().parent / "fingerprint.json"
    with open(fp_path, "w", encoding="utf-8") as handle:
        handle.write(fp.to_json())
    click.echo(f"[+] Fingerprint saved to {fp_path}")


@main.command()
@click.argument("cve_id")
def analyze(cve_id: str):
    """Analyze a CVE and produce an exploitation plan (without generating code)."""
    from angband.analysis.vuln_analyzer import VulnAnalyzer

    click.echo(f"[*] Analyzing {cve_id}...")
    analyzer = VulnAnalyzer()

    if cve_id.upper().startswith("CVE-"):
        plan = analyzer.analyze_cve(cve_id.upper())
    else:
        plan = analyzer.analyze_commit(cve_id)

    click.echo(f"\n[+] Analysis Results:")
    click.echo(f"    Bug class:       {plan.bug_class.value}")
    click.echo(f"    Subsystem:       {plan.subsystem.value}")
    click.echo(f"    Affected object: {plan.affected_object or 'unknown'}")
    click.echo(f"    Slab cache:      {plan.affected_slab_cache or 'unknown'}")
    click.echo(f"    Confidence:      {plan.confidence}")
    click.echo(f"\n[+] Exploitation Strategy:")
    click.echo(f"    Groom:           {plan.groom_technique or 'TBD'}")
    click.echo(f"    Leak:            {plan.leak_technique or 'TBD'}")
    click.echo(f"    Primitive:       {plan.primary_primitive or 'TBD'}")
    click.echo(f"    Escalation:      {plan.escalation_path.value}")
    click.echo(f"    Cleanup:         {plan.cleanup_method or 'TBD'}")

    if plan.description:
        click.echo(f"\n[+] Description: {plan.description[:200]}")


@main.command(name="list-primitives")
def list_primitives():
    """List available exploit primitives."""
    from angband.primitives.registry import PRIMITIVE_REGISTRY

    click.echo("[*] Available exploit primitives:\n")
    for name, cls in PRIMITIVE_REGISTRY.items():
        obj = cls()
        click.echo(f"  {name:25s} {obj.description}")


if __name__ == "__main__":
    main()
