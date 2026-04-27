from angband.stages.common import describe, require_demo_mode
from angband.runtime import default_config_path


def run(config: dict) -> bool:
    if not require_demo_mode(config):
        return False

    describe(config, "prep", "Environment checks and target validation")
    print(f"[Angband] exploit.yaml present: {default_config_path().exists()}")
    print(f"[Angband] target: {config.get('target', 'unknown')}")
    print(f"[Angband] mode: {config.get('mode', 'demo')}")
    return True
