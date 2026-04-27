from angband.stages.common import describe, notify_vuln_drill, require_demo_mode


def run(config: dict) -> bool:
    if not require_demo_mode(config):
        return False

    method = config.get("stages", {}).get("groom", {}).get("method", "simulation_only")
    describe(config, "groom", f"Simulating heap preparation with method '{method}'")
    notify_vuln_drill("groom")
    return True
