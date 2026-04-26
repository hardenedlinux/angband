from jinja2 import Environment, FileSystemLoader
from pathlib import Path

class PocGenerator:
    def __init__(self, template_dir="templates"):
        self.env = Environment(loader=FileSystemLoader(template_dir))
    
    def generate(self, config, output_path="exploit.c"):
        template = self.env.get_template("exploit.c.jinja2")
        
        # Extract variables from config
        context = {
            "exploit_name": config.get("exploit_name", "unknown_bug"),
            "target": config.get("target", "ubuntu-26.04-x86_64"),
            "groom_method": config.get("stages", {}).get("groom", {}).get("method"),
            "bug_type": config.get("stages", {}).get("trigger", {}).get("bug_type"),
        }
        
        rendered = template.render(context)
        with open(output_path, "w") as f:
            f.write(rendered)
        print(f"[Angband] PoC generated at {output_path}")
