from angband.stages.common import describe, notify_vuln_drill, require_demo_mode


def run(config: dict) -> bool:
    if not require_demo_mode(config):
        return False

    bug_type = config.get("stages", {}).get("trigger", {}).get("bug_type", "vuln_drill_demo")
    describe(config, "trigger", f"Trigger: '{bug_type}'")
    notify_vuln_drill("trigger")
    return True
