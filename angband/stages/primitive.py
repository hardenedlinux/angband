from angband.stages.common import describe, notify_vuln_drill, require_demo_mode


def run(config: dict) -> bool:
    if not require_demo_mode(config):
        return False

    method = config.get("recommended_primitive", "simulation_only")
    describe(config, "primitive", f"Exploit primitive: '{method}'")
    notify_vuln_drill("primitive")
    return True
