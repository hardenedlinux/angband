from angband.stages.common import describe, notify_vuln_drill, require_demo_mode


def run(config: dict) -> bool:
    if not require_demo_mode(config):
        return False

    method = config.get("stages", {}).get("leak", {}).get("method", "simulation_only")
    describe(config, "leak", f"KASLR bypass via '{method}'")
    notify_vuln_drill("leak")
    return True
