"""Kernel target fingerprinting via SSH into the QEMU guest.

Collects kernel version, config, slab allocator type, and active
mitigations so that downstream stages can make target-specific decisions.
"""

from __future__ import annotations

import json
import re
import subprocess
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional


@dataclass
class KernelFingerprint:
    """Structured representation of a target kernel environment."""

    # Basic identity
    kernel_release: str = ""              # e.g. "6.8.0-41-generic"
    kernel_version: str = ""              # e.g. "#41-Ubuntu SMP ..."
    arch: str = ""                        # e.g. "x86_64"
    hostname: str = ""

    # Kernel build config
    config_available: bool = False
    config_source: str = ""               # /boot/config-*, /proc/config.gz

    # Slab allocator
    slab_allocator: str = "unknown"       # slub, slab, slob

    # Mitigations
    kaslr: str = "unknown"
    smep: str = "unknown"
    smap: str = "unknown"
    kpti: str = "unknown"
    cfi: str = "unknown"
    cet: str = "unknown"
    selinux: str = "unknown"
    apparmor: str = "unknown"

    # Kernel symbols
    kallsyms_readable: bool = False
    kptr_restrict: int = -1

    # Slab cache info (useful for heap feng shui)
    slab_caches: dict = field(default_factory=dict)

    # Kernel modules loaded
    loaded_modules: list = field(default_factory=list)

    # Raw cmdline
    cmdline: str = ""

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    @property
    def mitigations_summary(self) -> dict:
        return {
            "kaslr": self.kaslr,
            "smep": self.smep,
            "smap": self.smap,
            "kpti": self.kpti,
            "cfi": self.cfi,
            "cet": self.cet,
            "selinux": self.selinux,
            "apparmor": self.apparmor,
        }


class TargetProbe:
    """Probes a QEMU guest via SSH to collect kernel fingerprint data."""

    def __init__(
        self,
        ssh_key: str | Path,
        host: str = "localhost",
        port: int = 2222,
        user: str = "ubuntu",
    ):
        self.ssh_key = str(ssh_key)
        self.host = host
        self.port = port
        self.user = user

    def _ssh_cmd(self, command: str, timeout: int = 10) -> str:
        """Execute a command on the guest via SSH, return stdout."""
        cmd = [
            "ssh",
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            "-o", "LogLevel=ERROR",
            "-i", self.ssh_key,
            "-p", str(self.port),
            f"{self.user}@{self.host}",
            command,
        ]
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout
            )
            return result.stdout.strip()
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return ""

    def _ssh_cmd_sudo(self, command: str, timeout: int = 10) -> str:
        """Execute a command with sudo on the guest."""
        return self._ssh_cmd(f"sudo {command}", timeout=timeout)

    def probe(self) -> KernelFingerprint:
        """Run all probes and return a populated KernelFingerprint."""
        fp = KernelFingerprint()

        # Basic identity
        fp.kernel_release = self._ssh_cmd("uname -r")
        fp.kernel_version = self._ssh_cmd("uname -v")
        fp.arch = self._ssh_cmd("uname -m")
        fp.hostname = self._ssh_cmd("hostname")
        fp.cmdline = self._ssh_cmd("cat /proc/cmdline")

        # Kernel config
        fp.config_available, fp.config_source = self._probe_kernel_config(fp.kernel_release)

        # Slab allocator
        fp.slab_allocator = self._probe_slab_allocator()

        # Mitigations from /proc/cmdline and CPU flags
        self._probe_mitigations(fp)

        # Kernel symbol access
        fp.kptr_restrict = self._probe_kptr_restrict()
        fp.kallsyms_readable = self._probe_kallsyms_readable()

        # Slab cache info
        fp.slab_caches = self._probe_slab_caches()

        # Loaded modules
        fp.loaded_modules = self._probe_modules()

        return fp

    def _probe_kernel_config(self, release: str) -> tuple[bool, str]:
        """Check for available kernel config."""
        # Try /boot/config-<release>
        boot_config = f"/boot/config-{release}"
        result = self._ssh_cmd(f"test -f {boot_config} && echo yes")
        if result == "yes":
            return True, boot_config

        # Try /proc/config.gz
        result = self._ssh_cmd("test -f /proc/config.gz && echo yes")
        if result == "yes":
            return True, "/proc/config.gz"

        return False, ""

    def _probe_slab_allocator(self) -> str:
        """Determine which slab allocator the kernel is using."""
        # Check /proc/slabinfo existence (SLUB and SLAB expose this)
        result = self._ssh_cmd_sudo("test -f /proc/slabinfo && echo yes")
        if result != "yes":
            return "unknown"

        # SLUB has /sys/kernel/slab/ directory
        result = self._ssh_cmd("test -d /sys/kernel/slab && echo yes")
        if result == "yes":
            return "slub"

        # If /proc/slabinfo exists but /sys/kernel/slab doesn't, likely SLAB
        return "slab"

    def _probe_mitigations(self, fp: KernelFingerprint) -> None:
        """Detect active kernel mitigations."""
        cmdline = fp.cmdline

        # KASLR: enabled by default, disabled by nokaslr
        if "nokaslr" in cmdline:
            fp.kaslr = "disabled"
        else:
            fp.kaslr = "enabled"

        # KPTI: check /sys/devices/system/cpu/vulnerabilities/meltdown
        vuln_meltdown = self._ssh_cmd("cat /sys/devices/system/cpu/vulnerabilities/meltdown 2>/dev/null")
        if "Mitigation: PTI" in vuln_meltdown:
            fp.kpti = "enabled"
        elif vuln_meltdown:
            fp.kpti = "disabled"

        # SMEP/SMAP: check CPU flags
        cpu_flags = self._ssh_cmd("grep -m1 flags /proc/cpuinfo")
        if "smep" in cpu_flags:
            fp.smep = "enabled"
        else:
            fp.smep = "disabled"

        if "smap" in cpu_flags:
            fp.smap = "enabled"
        else:
            fp.smap = "disabled"

        # CFI: check kernel config if available
        if fp.config_available and fp.config_source.startswith("/boot/"):
            cfi_result = self._ssh_cmd(f"grep CONFIG_CFI_CLANG {fp.config_source} 2>/dev/null")
            if "CONFIG_CFI_CLANG=y" in cfi_result:
                fp.cfi = "enabled"
            else:
                fp.cfi = "disabled"

        # CET: check CPU flags for shstk (shadow stack)
        if "shstk" in cpu_flags:
            fp.cet = "enabled"
        else:
            fp.cet = "disabled"

        # LSMs
        lsm_result = self._ssh_cmd("cat /sys/kernel/security/lsm 2>/dev/null")
        fp.selinux = "enabled" if "selinux" in lsm_result else "disabled"
        fp.apparmor = "enabled" if "apparmor" in lsm_result else "disabled"

    def _probe_kptr_restrict(self) -> int:
        """Read /proc/sys/kernel/kptr_restrict."""
        result = self._ssh_cmd("cat /proc/sys/kernel/kptr_restrict 2>/dev/null")
        try:
            return int(result)
        except ValueError:
            return -1

    def _probe_kallsyms_readable(self) -> bool:
        """Check if /proc/kallsyms exposes real addresses (not zeroed out)."""
        # With kptr_restrict >= 1, non-root sees zeros
        result = self._ssh_cmd_sudo("head -1 /proc/kallsyms 2>/dev/null")
        if not result:
            return False
        # If the address is all zeros, symbols are hidden
        parts = result.split()
        if parts and parts[0].replace("0", "") == "":
            return False
        return True

    def _probe_slab_caches(self) -> dict:
        """Parse /proc/slabinfo for slab cache sizes relevant to exploitation.

        Returns a dict of cache_name -> {objsize, active_objs, num_objs}.
        We focus on caches commonly targeted in kernel exploits.
        """
        INTERESTING_CACHES = [
            "kmalloc-8", "kmalloc-16", "kmalloc-32", "kmalloc-64",
            "kmalloc-96", "kmalloc-128", "kmalloc-192", "kmalloc-256",
            "kmalloc-512", "kmalloc-1k", "kmalloc-2k", "kmalloc-4k",
            "kmalloc-8k",
            "cred_jar",
            "files_cache",
            "filp",
            "msg_msg",
            "pipe_inode_info",
            "task_struct",
            "signal_cache",
            "sighand_cache",
            "inode_cache",
            "dentry",
            "sock_inode_cache",
        ]

        raw = self._ssh_cmd_sudo("cat /proc/slabinfo 2>/dev/null")
        if not raw:
            return {}

        caches = {}
        for line in raw.splitlines()[2:]:  # skip header lines
            parts = line.split()
            if len(parts) < 4:
                continue
            name = parts[0]
            if name in INTERESTING_CACHES or name.startswith("kmalloc-"):
                try:
                    caches[name] = {
                        "active_objs": int(parts[1]),
                        "num_objs": int(parts[2]),
                        "objsize": int(parts[3]),
                    }
                except (ValueError, IndexError):
                    continue

        return caches

    def _probe_modules(self) -> list:
        """List loaded kernel modules."""
        raw = self._ssh_cmd("lsmod 2>/dev/null")
        if not raw:
            return []
        modules = []
        for line in raw.splitlines()[1:]:  # skip header
            parts = line.split()
            if parts:
                modules.append(parts[0])
        return modules


def probe_local() -> KernelFingerprint:
    """Probe the local machine (for testing or host analysis).

    WARNING: This runs on the host. In production, always use
    TargetProbe to probe the QEMU guest.
    """
    import platform

    fp = KernelFingerprint()
    fp.kernel_release = platform.release()
    fp.kernel_version = platform.version()
    fp.arch = platform.machine()
    fp.hostname = platform.node()
    return fp


def get_config_value(
    ssh_key: str | Path,
    config_option: str,
    host: str = "localhost",
    port: int = 2222,
    user: str = "ubuntu",
) -> Optional[str]:
    """Quickly check a single kernel config option on the guest.

    Returns the value (e.g. 'y', 'm', 'n') or None if not found.
    """
    probe = TargetProbe(ssh_key, host, port, user)
    fp_config = probe._probe_kernel_config(probe._ssh_cmd("uname -r"))
    if not fp_config[0]:
        return None

    source = fp_config[1]
    if source.endswith(".gz"):
        raw = probe._ssh_cmd_sudo(f"zcat {source} | grep '^{config_option}='")
    else:
        raw = probe._ssh_cmd(f"grep '^{config_option}=' {source}")

    if "=" in raw:
        return raw.split("=", 1)[1]
    return None
