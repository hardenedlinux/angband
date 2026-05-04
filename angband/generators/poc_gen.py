from pathlib import Path

from jinja2 import Environment, FileSystemLoader


class PocGenerator:
    def __init__(self, template_dir: str | Path = "templates"):
        self.env = Environment(loader=FileSystemLoader(str(template_dir)))

    def generate(self, config, output_path: str = "exploit.c"):
        mode = config.get("mode", "demo")

        if mode == "exploit":
            template_name = "exploit_real.c.jinja2"
        else:
            template_name = "exploit.c.jinja2"

        template = self.env.get_template(template_name)

        context = {
            "exploit_name": config.get("exploit_name", "demo"),
            "reference_id": config.get("reference_id"),
            "target": config.get("target", "ubuntu-24.04-x86_64"),
            "mode": mode,
            "cve_profile": config.get("cve_profile", "generic"),
            "demo_profile": config.get("demo_profile", "vuln_drill"),
            "kernel_target": config.get("kernel_target", "none"),
            "scenario": config.get("scenario", ""),
            "groom_method": config.get("stages", {}).get("groom", {}).get("method", "simulation_only"),
            "bug_type": config.get("stages", {}).get("trigger", {}).get("bug_type", "vuln_drill_demo"),
            "trigger_method": config.get("stages", {}).get("trigger", {}).get("method", "simulation_only"),
            "leak_method": config.get("stages", {}).get("leak", {}).get("method", "simulation_only"),
            "primitive_method": config.get("stages", {}).get("primitive", {}).get("method", "simulation_only"),
            "escalate_method": config.get("stages", {}).get("escalate", {}).get("method", "simulation_only"),
            # Exploit-mode specific
            "bug_class": config.get("bug_class", "unknown"),
            "subsystem": config.get("subsystem", "other"),
            "affected_object": config.get("affected_object", ""),
            "affected_slab_cache": config.get("affected_slab_cache", ""),
            "object_size": config.get("object_size", 0),
            "escalation_path": config.get("escalation_path", "unknown"),
            "spray_count": config.get("stages", {}).get("groom", {}).get("spray_count", 256),
            "spray_msg_size": config.get("stages", {}).get("groom", {}).get("msg_size", 256),
            "groom_cache": config.get("stages", {}).get("groom", {}).get("cache", ""),
            "confidence": config.get("confidence", "low"),
            # Symbol offsets for KASLR bypass (from target config)
            "symbol_offsets": config.get("symbol_offsets", {}),
            "cve_symbol_offsets": config.get("cve_symbol_offsets", {}),
        }

        rendered = template.render(context)
        with open(output_path, "w", encoding="utf-8") as handle:
            handle.write(rendered)
        print(f"[Angband] Payload generated at {output_path} (mode={mode})")
