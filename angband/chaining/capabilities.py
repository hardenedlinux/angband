# angband/chaining/capabilities.py
"""Capability model for exploit chaining.

Each exploit stage can provide capabilities and require capabilities
from previous stages. This module tracks what's available and validates
that a stage can execute given the current context.
"""

from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Dict, List, Optional, Set, Tuple


class Capability(Enum):
    """Known capabilities that can flow between exploit stages."""

    # Info leaks
    KASLR_BYPASS = auto()          # Kernel base address known
    KERNEL_BASE = auto()           # kernel_base value
    MODPROBE_PATH_ADDR = auto()    # modprobe_path kernel address
    HEAP_ADDRESS = auto()          # Known heap object addresses
    KALLSYMS_ACCESS = auto()       # Can read /proc/kallsyms
    PCPU_BASE = auto()             # Per-CPU area base address

    # Privileges
    CAP_SYS_TIME = auto()          # CAP_SYS_TIME capability
    CAP_NET_ADMIN = auto()         # CAP_NET_ADMIN capability
    CAP_WAKE_ALARM = auto()        # CAP_WAKE_ALARM for alarm timers
    ROOT_UID = auto()              # Effective UID 0

    # Primitives
    KERNEL_WRITE = auto()          # Arbitrary kernel write primitive
    KERNEL_READ = auto()           # Arbitrary kernel read primitive
    KERNEL_CODE_EXEC = auto()      # Arbitrary kernel code execution
    ARBITRARY_FREE = auto()        # Arbitrary free primitive
    MODPROBE_OVERWRITE = auto()    # modprobe_path overwritten

    # Heap control
    UAF_CONDITION = auto()         # Use-after-free active
    HEAP_RECLAIM = auto()          # Freed memory reclaimed
    MSG_MSG_SPRAYED = auto()       # msg_msg objects sprayed
    PIPE_SPRAYED = auto()          # Pipe buffer objects sprayed
    SLAB_DRAINED = auto()          # Target slab cache drained

    # Trigger conditions
    CLOCK_WAS_SET = auto()         # clock_was_set() triggered
    TIMERFD_DUP_AVAILABLE = auto() # Dup'd timerfd fds exist

    # Namespace
    USER_NAMESPACE = auto()        # In user namespace
    NET_NAMESPACE = auto()         # In network namespace

    # Exploitation final
    ROOT_SHELL = auto()            # Privilege escalation achieved


# Registry mapping capabilities to what they enable
CAPABILITY_REGISTRY: Dict[Capability, Dict] = {
    Capability.KASLR_BYPASS: {
        "description": "Kernel base address is known (defeats KASLR)",
        "enables": [Capability.MODPROBE_PATH_ADDR, Capability.PCPU_BASE],
        "provided_by": ["kaslr_leak_kallsyms_parent", "kaslr_leak_sidechannel",
                       "infoleak_primitive"],
    },
    Capability.CAP_SYS_TIME: {
        "description": "Process has CAP_SYS_TIME to call settimeofday()",
        "enables": [Capability.CLOCK_WAS_SET],
        "provided_by": ["user_namespace_cap", "setuid_binary", "capability_bug"],
    },
    Capability.CLOCK_WAS_SET: {
        "description": "clock_was_set() invoked, triggers cancel_list write",
        "enables": [Capability.UAF_CONDITION],
        "provided_by": ["settimeofday_syscall", "timerfd_resume"],
    },
    Capability.KERNEL_WRITE: {
        "description": "Arbitrary kernel memory write primitive",
        "enables": [Capability.MODPROBE_OVERWRITE, Capability.KERNEL_CODE_EXEC],
        "provided_by": ["pcpu_stats_corruption", "msg_msg_corruption",
                       "dirty_pagetable", "oob_write"],
    },
    Capability.MODPROBE_OVERWRITE: {
        "description": "modprobe_path overwritten with payload path",
        "enables": [Capability.ROOT_SHELL],
        "provided_by": ["modprobe_path_write"],
    },
    Capability.ROOT_SHELL: {
        "description": "Privilege escalation achieved (euid=0)",
        "enables": [],
        "provided_by": ["modprobe_trigger", "commit_creds_call"],
    },
}


class CapabilityChecker:
    """Tracks available capabilities and validates stage requirements."""

    def __init__(self, initial_context: Optional[Dict] = None):
        self._capabilities: Set[Capability] = set()
        self._context: Dict = initial_context or {}

    def grant(self, capability: Capability) -> None:
        """Grant a capability and all capabilities it enables."""
        if capability in self._capabilities:
            return
        self._capabilities.add(capability)
        # Recursively grant enabled capabilities
        registry = CAPABILITY_REGISTRY.get(capability)
        if registry:
            for enabled in registry.get("enables", []):
                self.grant(enabled)

    def has(self, capability: Capability) -> bool:
        """Check if a capability is available."""
        return capability in self._capabilities

    def check_all(self, required: List[Capability]) -> Tuple[bool, List[str]]:
        """Check all required capabilities and return missing ones."""
        missing = []
        for cap in required:
            if not self.has(cap):
                missing.append(str(cap))
        return len(missing) == 0, missing

    def can_execute_stage(self, stage_config: Dict) -> Tuple[bool, str]:
        """Check if a stage can execute given available capabilities."""
        requires = stage_config.get("requires", [])
        for req_name in requires:
            try:
                cap = Capability[req_name.upper()]
            except KeyError:
                cap = None
            if cap and not self.has(cap):
                return False, f"Missing capability: {req_name}"
        return True, "OK"

    def update_context(self, new_data: Dict) -> None:
        """Add data to the shared context."""
        self._context.update(new_data)

    def get_context(self, key: str, default=None):
        """Get a value from shared context."""
        return self._context.get(key, default)

    @property
    def available(self) -> Set[Capability]:
        """Return all currently available capabilities."""
        return self._capabilities.copy()

    @property
    def context(self) -> Dict:
        """Return the shared context."""
        return dict(self._context)

    def summary(self) -> str:
        """Human-readable summary of available capabilities."""
        lines = []
        for cap in sorted(self._capabilities, key=lambda c: c.name):
            registry = CAPABILITY_REGISTRY.get(cap, {})
            desc = registry.get("description", "")
            lines.append(f"  [{cap.name}] {desc}")
        return "\n".join(lines) if lines else "  (none)"


# CVE-specific stage capability mappings

STAGE_CAPABILITIES: Dict[str, Tuple[List[Capability], List[Capability]]] = {
    # (requires, provides) for each CVE profile + stage combination

    # CVE-2026-23209 (macvlan UAF) - self-contained exploitation
    "macvlan_uaf_groom": ([], [
        Capability.MSG_MSG_SPRAYED,
        Capability.SLAB_DRAINED,
    ]),
    "macvlan_uaf_trigger": ([Capability.CAP_NET_ADMIN], [
        Capability.UAF_CONDITION,
    ]),
    "macvlan_uaf_leak": ([], [
        Capability.KASLR_BYPASS,
        Capability.KERNEL_BASE,
        Capability.MODPROBE_PATH_ADDR,
        Capability.KALLSYMS_ACCESS,
    ]),
    "macvlan_uaf_primitive": ([
        Capability.UAF_CONDITION,
        Capability.KASLR_BYPASS,
        Capability.MODPROBE_PATH_ADDR,
    ], [
        Capability.KERNEL_WRITE,
    ]),
    "macvlan_uaf_escalate": ([
        Capability.KERNEL_WRITE,
        Capability.MODPROBE_PATH_ADDR,
    ], [
        Capability.MODPROBE_OVERWRITE,
        Capability.ROOT_SHELL,
    ]),
}
