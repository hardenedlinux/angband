"""Stage engine for orchestrating kernel exploitation pipeline."""
from pathlib import Path
import yaml
from typing import Dict, Any

class StageEngine:
    def __init__(self, config_path: str = "exploit.yaml"):
        self.config = self._load_config(config_path)
        self.stages = ["prep", "groom", "trigger", "leak", "primitive", "escalate", "cleanup"]
    
    def _load_config(self, path: str) -> Dict[str, Any]:
        with open(path, "r") as f:
            return yaml.safe_load(f)
    
    def run_stage(self, stage_name: str):
        print(f"[Angband] Executing stage: {stage_name}")
        config = self.config or {}
        if stage_name == "prep":
            from angband.stages.prep import run as prep_run
            return prep_run(config)
        elif stage_name == "groom":
            from angband.stages.groom import run as groom_run
            return groom_run(config)
        elif stage_name == "trigger":
            from angband.stages.trigger import run as trigger_run
            return trigger_run(config)
        elif stage_name == "leak":
            from angband.stages.leak import run as leak_run
            return leak_run(config)
        elif stage_name == "primitive":
            from angband.stages.primitive import run as primitive_run
            return primitive_run(config)
        elif stage_name == "escalate":
            from angband.stages.escalate import run as escalate_run
            return escalate_run(config)
        elif stage_name == "cleanup":
            from angband.stages.cleanup import run as cleanup_run
            return cleanup_run(config)
        print(f"  [Stage] {stage_name} - placeholder (plugin not yet implemented)")
        return True
    
    def run_pipeline(self):
        print("[Angband] Starting full exploitation pipeline")
        success = True
        for stage in self.stages:
            if not self.run_stage(stage):
                print(f"[!] Stage {stage} failed. Falling back to recovery mode.")
                success = False
                break
        
        if not success:
            print("[Angband] Triggering automated recovery & alternative grooming strategy...")
            self.run_stage("cleanup")
        else:
            print("[Angband] Pipeline completed successfully")