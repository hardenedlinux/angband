from pathlib import Path


PROC_PATH = Path("/proc/vuln_drill")


def describe(config: dict, stage: str, message: str) -> None:
    scenario = config.get("scenario", "Safe walkthrough")
    print(f"[Angband] {stage}: {message}")
    print(f"[Angband] Scenario: {scenario}")


def notify_vuln_drill(stage: str) -> bool:
    if not PROC_PATH.exists():
        print("[Angband] vuln_drill is not present; running in offline simulation mode")
        return False

    try:
        PROC_PATH.write_text(f"{stage}\n", encoding="utf-8")
        print(f"[Angband] Recorded stage '{stage}' in /proc/vuln_drill")
        return True
    except OSError as exc:
        print(f"[Angband] Unable to write to /proc/vuln_drill: {exc}")
        return False


def require_demo_mode(config: dict) -> bool:
    mode = config.get("mode", "demo")
    if mode not in ("demo", "exploit"):
        print(f"[Angband] Unsupported mode '{mode}'. Use 'demo' or 'exploit'.")
        return False
    return True


def target_kernel_release() -> str | None:
    """Read the target kernel release from fingerprint or local uname."""
    import json
    import subprocess

    fp_path = Path("mordor_run/current/fingerprint.json")
    if fp_path.exists():
        try:
            with open(fp_path) as f:
                data = json.load(f)
            return data.get("kernel_release")
        except (json.JSONDecodeError, OSError):
            pass

    try:
        return subprocess.check_output(
            ["uname", "-r"], text=True
        ).strip()
    except (subprocess.SubprocessError, FileNotFoundError):
        return None
