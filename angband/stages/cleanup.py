from angband.stages.common import describe, notify_vuln_drill, require_demo_mode


def run(config: dict) -> bool:
    if not require_demo_mode(config):
        return False

    describe(config, "cleanup", "Closing out the demo and restoring a clean narrative state")
    notify_vuln_drill("cleanup")
    print("[Angband] Cleanup complete")
    return True
