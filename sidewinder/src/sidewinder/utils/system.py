"""System utilities for sidewinder."""

import os
import platform
import subprocess
import re


def kernel_version() -> str:
    return platform.release()


def kernel_version_tuple() -> tuple:
    v = platform.release().split("-")[0]
    return tuple(int(x) for x in v.split("."))


def is_root() -> bool:
    return os.geteuid() == 0


def num_cpus() -> int:
    return os.cpu_count() or 1


def pagemap_available() -> bool:
    try:
        fd = os.open("/proc/self/pagemap", os.O_RDONLY)
        os.close(fd)
        return True
    except (PermissionError, OSError):
        return False


def hugepages_available() -> bool:
    return os.path.exists("/proc/sys/vm/nr_hugepages")


def kptr_restrict() -> int:
    try:
        with open("/proc/sys/kernel/kptr_restrict") as f:
            return int(f.read().strip())
    except Exception:
        return -1


def dmesg_restrict() -> int:
    try:
        with open("/proc/sys/kernel/dmesg_restrict") as f:
            return int(f.read().strip())
    except Exception:
        return -1


def kernel_config_items() -> dict:
    config = {}
    try:
        result = subprocess.run(
            ["zcat", "/proc/config.gz"], capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            for line in result.stdout.splitlines():
                line = line.strip()
                if line.startswith("CONFIG_"):
                    k, _, v = line.partition("=")
                    config[k] = v.strip('"')
    except Exception:
        pass

    try:
        result = subprocess.run(
            ["cat", f"/boot/config-{platform.release()}"], capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            for line in result.stdout.splitlines():
                line = line.strip()
                if line.startswith("CONFIG_"):
                    k, _, v = line.partition("=")
                    if k not in config:
                        config[k] = v.strip('"')
    except Exception:
        pass

    return config


def read_sysfs(path: str) -> str:
    try:
        with open(path) as f:
            return f.read().strip()
    except Exception:
        return ""


def read_msr(cpu: int, msr: int) -> int | None:
    try:
        fd = os.open(f"/dev/cpu/{cpu}/msr", os.O_RDONLY)
        os.lseek(fd, msr, os.SEEK_SET)
        data = os.read(fd, 8)
        os.close(fd)
        return int.from_bytes(data, "little")
    except Exception:
        return None


def read_cpuid_leaf(leaf: int, subleaf: int = 0) -> tuple:
    try:
        result = subprocess.run(
            ["cpuid", "-1", "-l", str(leaf), "-s", str(subleaf)],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            eax = ebx = ecx = edx = 0
            for line in result.stdout.splitlines():
                m = re.match(r"\s*EAX=0x([0-9a-fA-F]+)", line)
                if m: eax = int(m.group(1), 16)
                m = re.match(r"\s*EBX=0x([0-9a-fA-F]+)", line)
                if m: ebx = int(m.group(1), 16)
                m = re.match(r"\s*ECX=0x([0-9a-fA-F]+)", line)
                if m: ecx = int(m.group(1), 16)
                m = re.match(r"\s*EDX=0x([0-9a-fA-F]+)", line)
                if m: edx = int(m.group(1), 16)
            return (eax, ebx, ecx, edx)
    except Exception:
        pass
    return (0, 0, 0, 0)


def find_shared_library(name: str) -> str | None:
    try:
        result = subprocess.run(
            ["ldconfig", "-p"], capture_output=True, text=True, timeout=5
        )
        for line in result.stdout.splitlines():
            if name in line:
                parts = line.strip().split(" => ")
                if len(parts) == 2:
                    path = parts[1].strip()
                    if os.path.exists(path):
                        return path
    except Exception:
        pass

    common_paths = [
        f"/usr/lib/x86_64-linux-gnu/{name}",
        f"/usr/lib/{name}",
        f"/lib/x86_64-linux-gnu/{name}",
        f"/lib/{name}",
    ]
    for p in common_paths:
        if os.path.exists(p):
            return p
    return None
