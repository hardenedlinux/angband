import re
from pathlib import Path

from jinja2 import Environment, FileSystemLoader


CUSTOM_BLOCK_START = "/* CUSTOM_IMPL_START"
CUSTOM_BLOCK_END = "CUSTOM_IMPL_END */"


class PocGenerator:
    def __init__(self, template_dir: str | Path = "templates"):
        self.env = Environment(loader=FileSystemLoader(str(template_dir)))

    def _has_custom_code(self, content: str) -> bool:
        """Check if content has any custom implementation markers."""
        return CUSTOM_BLOCK_START in content

    def _extract_custom_blocks(self, existing_content: str) -> dict[str, str]:
        """Extract custom implementation blocks marked in existing file."""
        blocks = {}
        pattern = re.compile(
            rf'{re.escape(CUSTOM_BLOCK_START)}_(\w+)\n(.*?)\n{re.escape(CUSTOM_BLOCK_END)}',
            re.DOTALL
        )
        for match in pattern.finditer(existing_content):
            blocks[match.group(1)] = match.group(2)
        return blocks

    def _merge_custom_blocks(self, new_content: str, blocks: dict[str, str]) -> str:
        """Merge custom blocks into generated content at marker positions."""
        result = new_content
        for stage_name, custom_code in blocks.items():
            marker = f"{CUSTOM_BLOCK_START}_{stage_name}\n"
            if marker in result:
                # Replace marker + placeholder with marker + custom code
                pattern = rf'({re.escape(marker)}).*?({re.escape(CUSTOM_BLOCK_END)})'
                replacement = rf'\1\n{custom_code}\n\CUSTOM_BLOCK_END)'
                result = re.sub(pattern, replacement, result, flags=re.DOTALL)
        return result

    def generate(self, config, output_path: str = "exploit.c", preserve: bool = True):
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

        # If preserve=True and existing file has custom code, skip regeneration
        output_path_obj = Path(output_path)
        if preserve and output_path_obj.exists():
            existing = output_path_obj.read_text(encoding="utf-8")
            if self._has_custom_code(existing):
                print(f"[Angband] Skipping regeneration - custom code detected in {output_path}")
                print(f"[Angband] Run with --no-preserve to force regeneration")
                return

            # Try to merge custom blocks into new template
            custom_blocks = self._extract_custom_blocks(existing)
            if custom_blocks:
                rendered = self._merge_custom_blocks(rendered, custom_blocks)
                print(f"[Angband] Preserved {len(custom_blocks)} custom block(s)")

        with open(output_path, "w", encoding="utf-8") as handle:
            handle.write(rendered)
        print(f"[Angband] Payload generated at {output_path} (mode={mode})")
