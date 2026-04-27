"""Stage engine for the Angband exploit pipeline.

Supports two modes:
- demo: Safe walkthrough with stage recording via vuln_drill
- exploit: Real exploit execution through the same 7-stage pipeline
"""

from importlib import import_module
from typing import Any, Dict

import yaml

from angband.runtime import default_config_path


class StageEngine:
    def __init__(self, config_path: str | None = None):
        config_path = config_path or str(default_config_path())
        self.config = self._load_config(config_path)
        self.stages = ["prep", "groom", "trigger", "leak", "primitive", "escalate", "cleanup"]

    def _load_config(self, path: str) -> Dict[str, Any]:
        with open(path, "r", encoding="utf-8") as handle:
            return yaml.safe_load(handle) or {}

    @property
    def mode(self) -> str:
        return self.config.get("mode", "demo")

    def run_stage(self, stage_name: str) -> bool:
        mode = self.mode
        print(f"[Angband] Executing stage: {stage_name} (mode={mode})")

        if stage_name not in self.stages:
            print(f"[!] Unknown stage: {stage_name}")
            return False

        module = import_module(f"angband.stages.{stage_name}")
        return bool(module.run(self.config))

    def run_pipeline(self) -> bool:
        mode = self.mode
        print(f"[Angband] Starting pipeline (mode={mode})")

        for stage in self.stages:
            if not self.run_stage(stage):
                print(f"[!] Stage {stage} failed. Aborting pipeline.")
                return False

        if mode == "exploit":
            print("[Angband] Exploit pipeline completed - check for uid=0")
        else:
            print("[Angband] Demo pipeline completed successfully")
        return True
