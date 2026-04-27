from pathlib import Path


RUNTIME_ROOT_NAME = "mordor_run"


def workspace_root() -> Path:
    cwd = Path.cwd()
    if (cwd / "configs").exists() and (cwd / "templates").exists():
        return cwd
    return Path(__file__).resolve().parents[1]


def runtime_root() -> Path:
    return workspace_root() / RUNTIME_ROOT_NAME


def current_run_dir() -> Path:
    return runtime_root() / "current"


def harness_run_dir() -> Path:
    return runtime_root() / "harness"


def cache_dir() -> Path:
    return runtime_root() / "cache"


def ssh_dir() -> Path:
    return runtime_root() / "ssh"


def ensure_runtime_dirs() -> None:
    for path in (runtime_root(), current_run_dir(), harness_run_dir(), cache_dir(), ssh_dir()):
        path.mkdir(parents=True, exist_ok=True)


def default_config_path() -> Path:
    return current_run_dir() / "exploit.yaml"


def default_source_path() -> Path:
    return current_run_dir() / "exploit.c"


def default_binary_path() -> Path:
    return current_run_dir() / "exploit"
