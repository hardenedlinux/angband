#!/usr/bin/env python3
import click
import yaml
from pathlib import Path
from angband.core.engine import StageEngine

@click.group()
@click.version_option("0.1.0")
def main():
    """Angband - Kernel Exploit Framework"""
    pass

@main.command()
@click.argument("cve_or_commit")
@click.option("--target", default="ubuntu-26.04-x86_64", help="Target config")
def init(cve_or_commit: str, target: str):
    """Step 1: Initialize a new exploit project from a CVE or commit"""
    click.echo(f"[*] Initializing exploit project for {cve_or_commit}")
    click.echo(f"[*] Target distribution: {target}")
    
    # In a real tool, this would fetch details about the CVE/commit to set up the config
    config_path = Path("exploit.yaml")
    
    # Read the default target config to inherit strategies
    target_config_path = Path(f"configs/{target}.yaml")
    config_content = f"exploit_name: {cve_or_commit}\n"
    
    if target_config_path.exists():
        with open(target_config_path, "r") as f:
            target_data = yaml.safe_load(f)
            # Dump the relevant stages and primitives into the local exploit.yaml
            if "stages" in target_data:
                config_content += "stages:\n"
                for stage_name, stage_data in target_data["stages"].items():
                    config_content += f"  {stage_name}:\n"
                    for k, v in stage_data.items():
                        config_content += f"    {k}: {v}\n"
            if "recommended_primitive" in target_data:
                config_content += f"recommended_primitive: {target_data['recommended_primitive']}\n"
            config_content += f"target: {target}\n"
    else:
        # Create a basic fallback config
        config_content = f"""exploit_name: {cve_or_commit}
target: {target}
stages:
  groom:
    method: cross_cache
    objects: ["msg_msg", "pipe_buffer"]
  trigger:
    bug_type: unknown
  escalation:
    method: dirty_cred
    cfi_aware: true
"""
    with open(config_path, "w") as f:
        f.write(config_content)
        
    click.echo(f"[+] Created {config_path}")
    click.echo("[*] Next step: 'angband build-env' or 'angband generate'")

@main.command()
def build_env():
    """Step 2: Build or download the target environment (QEMU image)"""
    click.echo("[*] Setting up target environment...")
    
    config = {}
    if Path("exploit.yaml").exists():
        with open("exploit.yaml", "r") as f:
            config = yaml.safe_load(f)
            
    target = config.get("target", "ubuntu-26.04-x86_64")
    click.echo(f"[*] Target: {target}")
    click.echo("[*] Running harness setup scripts...")
    click.echo("[+] Environment ready. Use 'cd harness && ./launch.sh' to boot.")

@main.command()
@click.option("--output", default="exploit.c", help="Output C file")
def generate(output: str):
    """Step 3: Generate the PoC/Exploit code"""
    from angband.generators.poc_gen import PocGenerator
    import subprocess
    
    if not Path("exploit.yaml").exists():
        click.echo("[!] exploit.yaml not found. Run 'angband init' first.")
        return
        
    with open("exploit.yaml", "r") as f:
        config = yaml.safe_load(f)
        
    click.echo(f"[*] Generating exploit C code from {config.get('exploit_name')}...")
    gen = PocGenerator("templates")
    gen.generate(config, output)
    
    click.echo(f"[+] Exploit generated: {output}")
    
    # Auto-compile attempt
    click.echo("[*] Attempting compilation...")
    compile_cmd = ["gcc", "-o", "exploit", output, "primitives/msg_msg.c", "primitives/pipe_buffer.c", "primitives/dirty_cred.c", "-I."]
    result = subprocess.run(compile_cmd, capture_output=True, text=True)
    
    if result.returncode == 0:
        click.echo("[+] Successfully compiled 'exploit'")
    else:
        click.echo(f"[!] Compilation failed:\n{result.stderr}")
    
    click.echo("[*] Test it in QEMU: cd harness && ./launch.sh")


@main.command()
@click.argument("stage")
def run_stage(stage: str):
    """Run a specific exploitation stage"""
    engine = StageEngine("exploit.yaml")
    success = engine.run_stage(stage)
    click.echo(f"Stage {stage} completed: {'SUCCESS' if success else 'FAILED'}")

@main.command()
@click.option("--config", default="exploit.yaml")
def pipeline(config: str):
    """Run full exploitation pipeline"""
    engine = StageEngine(config)
    engine.run_pipeline()
    click.echo("Full pipeline completed successfully.")

if __name__ == "__main__":
    main()