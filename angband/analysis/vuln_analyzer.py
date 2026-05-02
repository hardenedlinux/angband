"""Vulnerability analysis engine: CVE -> bug class -> exploitation strategy.

This module is the 'brain' of Angband.  Given a CVE identifier, it:

1. Fetches CVE metadata from NVD and/or kernel git history
2. Identifies the bug class (UAF, double-free, OOB, race, type confusion, etc.)
3. Determines the affected kernel subsystem and slab cache
4. Selects an exploitation strategy (which primitives to use, which
   leak technique, which escalation path)
5. Emits a structured ExploitPlan that the code generator consumes

The analysis can operate in multiple modes:
- **NVD mode**: Fetch from NIST NVD API (requires network)
- **Patch mode**: Analyze a git commit diff directly
- **Manual mode**: User provides bug class and subsystem
"""

from __future__ import annotations

import json
import re
import subprocess
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Optional


# ---------------------------------------------------------------------------
# Bug classification
# ---------------------------------------------------------------------------

class BugClass(Enum):
    """Kernel vulnerability bug classes."""
    USE_AFTER_FREE = "use_after_free"
    DOUBLE_FREE = "double_free"
    OUT_OF_BOUNDS_READ = "oob_read"
    OUT_OF_BOUNDS_WRITE = "oob_write"
    TYPE_CONFUSION = "type_confusion"
    RACE_CONDITION = "race_condition"
    INTEGER_OVERFLOW = "integer_overflow"
    NULL_PTR_DEREF = "null_ptr_deref"
    STACK_OVERFLOW = "stack_overflow"
    UNINITIALIZED_MEMORY = "uninit_memory"
    REFERENCE_COUNT = "refcount"
    UNKNOWN = "unknown"


class Subsystem(Enum):
    """Major kernel subsystems."""
    NETFILTER = "netfilter"
    NETWORK_STACK = "network"
    FILESYSTEM = "filesystem"
    MEMORY_MANAGEMENT = "mm"
    BLOCK_DEVICE = "block"
    USB = "usb"
    BLUETOOTH = "bluetooth"
    IPC = "ipc"
    SCHEDULER = "scheduler"
    IO_URING = "io_uring"
    BPF = "bpf"
    NFTABLES = "nftables"
    CRYPTO = "crypto"
    SOUND = "sound"
    DRM_GPU = "drm"
    CGROUP = "cgroup"
    NAMESPACE = "namespace"
    OTHER = "other"


class EscalationPath(Enum):
    """Privilege escalation strategies."""
    MODPROBE_PATH = "modprobe_path"
    DIRTY_PAGETABLE = "dirty_pagetable"
    DIRTY_CRED = "dirty_cred"
    COMMIT_CREDS = "commit_creds"        # overwrite cred via arb write
    ROP_CHAIN = "rop_chain"              # stack pivot + ROP to commit_creds
    PIPE_PRIMITIVE = "pipe_primitive"     # arbitrary r/w via pipe_buffer
    MSG_MSG_PRIMITIVE = "msg_msg_primitive"
    USMA = "usma"                        # user-space mapping attack
    UNKNOWN = "unknown"


# ---------------------------------------------------------------------------
# Exploit plan
# ---------------------------------------------------------------------------

@dataclass
class ExploitPlan:
    """Complete exploitation strategy derived from vulnerability analysis."""

    # CVE identity
    cve_id: str = ""
    commit_hash: str = ""
    description: str = ""
    cve_profile: str = "generic"     # template profile name (e.g. "macvlan_uaf")

    # Version range
    introduced_in: str = ""  # kernel version where the bug was introduced
    fixed_in: str = ""       # kernel version where the bug was fixed
    ubuntu_fixed: str = ""   # Ubuntu kernel package version that fixes it

    # Bug characterization
    bug_class: BugClass = BugClass.UNKNOWN
    subsystem: Subsystem = Subsystem.OTHER
    affected_object: str = ""           # e.g., "nft_set_elem", "sk_buff"
    affected_slab_cache: str = ""       # e.g., "kmalloc-256"
    object_size: int = 0                # size of the vulnerable object

    # Affected versions
    introduced_in: str = ""             # kernel version
    fixed_in: str = ""                  # kernel version

    # Exploitation strategy
    groom_technique: str = ""           # e.g., "msg_msg_spray", "pipe_buffer_spray"
    groom_cache: str = ""               # target slab cache for grooming
    trigger_method: str = ""            # how to trigger the bug
    leak_technique: str = ""            # KASLR bypass method
    primary_primitive: str = ""         # main r/w primitive
    escalation_path: EscalationPath = EscalationPath.UNKNOWN
    cleanup_method: str = ""            # how to stabilize the kernel after

    # Code generation hints
    requires_namespaces: bool = False   # needs user namespaces
    requires_userfaultfd: bool = False  # needs userfaultfd (often disabled)
    requires_io_uring: bool = False
    requires_unprivileged_bpf: bool = False
    race_window_us: int = 0             # estimated race window in microseconds
    spray_count: int = 0                # number of objects to spray

    # Confidence
    confidence: str = "low"             # low, medium, high

    def to_dict(self) -> dict:
        d = {}
        for k, v in self.__dict__.items():
            if isinstance(v, Enum):
                d[k] = v.value
            else:
                d[k] = v
        return d

    def to_yaml_config(self) -> dict:
        """Convert to the exploit.yaml config format used by angband."""
        return {
            "exploit_name": self.cve_id or "unknown",
            "reference_id": self.cve_id,
            "mode": "exploit",
            "cve_profile": getattr(self, "cve_profile", "generic"),
            "demo_profile": "cve_exploit",
            "kernel_target": "real",
            "scenario": self.description or f"Full-chain exploit for {self.cve_id}",
            "target": "",  # filled in by CLI
            "recommended_primitive": self.primary_primitive,
            "bug_class": self.bug_class.value,
            "subsystem": self.subsystem.value,
            "affected_object": self.affected_object,
            "affected_slab_cache": self.affected_slab_cache,
            "object_size": self.object_size,
            "escalation_path": self.escalation_path.value,
            "confidence": self.confidence,
            "stages": {
                "prep": {"method": "environment_checks"},
                "groom": {
                    "method": self.groom_technique or "simulation_only",
                    "cache": self.groom_cache,
                    "spray_count": self.spray_count,
                    "msg_size": self.object_size - 48 if self.object_size > 48 else 256,
                },
                "trigger": {
                    "bug_type": self.bug_class.value,
                    "method": self.trigger_method or "simulation_only",
                },
                "leak": {
                    "method": self.leak_technique or "simulation_only",
                },
                "primitive": {
                    "method": self.primary_primitive or "simulation_only",
                },
                "escalate": {
                    "method": self.escalation_path.value,
                },
                "cleanup": {
                    "method": self.cleanup_method or "safe_reset",
                },
            },
        }


# ---------------------------------------------------------------------------
# Bug class detection from patch / description
# ---------------------------------------------------------------------------

# Patterns to detect bug class from commit messages and diffs
BUG_PATTERNS = {
    BugClass.USE_AFTER_FREE: [
        r"use.after.free", r"uaf", r"dangling\s+pointer",
        r"freed.*accessed", r"access.*after.*free",
    ],
    BugClass.DOUBLE_FREE: [
        r"double.free", r"freed\s+twice", r"double\s+kfree",
    ],
    BugClass.OUT_OF_BOUNDS_WRITE: [
        r"out.of.bound.*write", r"oob.*write", r"heap.overflow",
        r"buffer\s+overflow", r"write.*beyond",
    ],
    BugClass.OUT_OF_BOUNDS_READ: [
        r"out.of.bound.*read", r"oob.*read", r"information\s+leak",
        r"read.*beyond", r"over.read",
    ],
    BugClass.RACE_CONDITION: [
        r"race\s+condition", r"toctou", r"data\s+race",
        r"concurrency", r"missing\s+lock",
    ],
    BugClass.TYPE_CONFUSION: [
        r"type\s+confusion", r"cast.*incorrect",
    ],
    BugClass.INTEGER_OVERFLOW: [
        r"integer\s+overflow", r"int\s+overflow", r"arithmetic\s+overflow",
    ],
    BugClass.NULL_PTR_DEREF: [
        r"null\s+pointer", r"null\s+deref", r"nullptr",
    ],
    BugClass.REFERENCE_COUNT: [
        r"refcount", r"reference\s+count", r"ref.*leak",
    ],
    BugClass.UNINITIALIZED_MEMORY: [
        r"uninitialized", r"uninit", r"info.*leak",
    ],
}

# Patterns to detect subsystem from file paths
SUBSYSTEM_PATTERNS = {
    Subsystem.NETFILTER: [r"net/netfilter", r"nf_", r"nft_"],
    Subsystem.NFTABLES: [r"nf_tables", r"nft_"],
    Subsystem.NETWORK_STACK: [r"net/", r"sk_buff", r"socket", r"tcp", r"udp"],
    Subsystem.IO_URING: [r"io_uring"],
    Subsystem.BPF: [r"kernel/bpf", r"net/bpf"],
    Subsystem.FILESYSTEM: [r"fs/", r"ext4", r"btrfs", r"xfs"],
    Subsystem.MEMORY_MANAGEMENT: [r"mm/", r"vmalloc", r"slab"],
    Subsystem.USB: [r"drivers/usb", r"usb_"],
    Subsystem.BLUETOOTH: [r"net/bluetooth", r"drivers/bluetooth"],
    Subsystem.IPC: [r"ipc/"],
    Subsystem.CGROUP: [r"kernel/cgroup"],
    Subsystem.NAMESPACE: [r"kernel/nsproxy", r"user_namespace"],
    Subsystem.BLOCK_DEVICE: [r"block/", r"drivers/block"],
    Subsystem.SOUND: [r"sound/"],
    Subsystem.DRM_GPU: [r"drivers/gpu"],
    Subsystem.CRYPTO: [r"crypto/"],
}


def detect_bug_class(text: str) -> BugClass:
    """Detect the bug class from a commit message or CVE description."""
    text_lower = text.lower()
    for bug_class, patterns in BUG_PATTERNS.items():
        for pattern in patterns:
            if re.search(pattern, text_lower):
                return bug_class
    return BugClass.UNKNOWN


def detect_subsystem(file_paths: list[str], text: str = "") -> Subsystem:
    """Detect the kernel subsystem from affected file paths."""
    combined = " ".join(file_paths) + " " + text
    combined_lower = combined.lower()
    for subsystem, patterns in SUBSYSTEM_PATTERNS.items():
        for pattern in patterns:
            if re.search(pattern, combined_lower):
                return subsystem
    return Subsystem.OTHER


# ---------------------------------------------------------------------------
# Strategy selection based on bug class
# ---------------------------------------------------------------------------

# Maps bug class to recommended exploitation strategies
STRATEGY_MAP = {
    BugClass.USE_AFTER_FREE: {
        "groom_techniques": ["msg_msg_spray", "pipe_buffer_spray"],
        "leak_techniques": ["pipe_buffer_ops", "msg_msg_oob"],
        "primitives": ["pipe_primitive", "msg_msg_primitive"],
        "escalation": [EscalationPath.DIRTY_PAGETABLE, EscalationPath.MODPROBE_PATH],
    },
    BugClass.DOUBLE_FREE: {
        "groom_techniques": ["msg_msg_spray", "pipe_buffer_spray"],
        "leak_techniques": ["pipe_buffer_ops", "msg_msg_oob"],
        "primitives": ["pipe_primitive", "msg_msg_primitive"],
        "escalation": [EscalationPath.DIRTY_PAGETABLE, EscalationPath.DIRTY_CRED],
    },
    BugClass.OUT_OF_BOUNDS_WRITE: {
        "groom_techniques": ["msg_msg_spray", "setxattr_spray"],
        "leak_techniques": ["msg_msg_oob"],
        "primitives": ["msg_msg_primitive"],
        "escalation": [EscalationPath.MODPROBE_PATH, EscalationPath.ROP_CHAIN],
    },
    BugClass.OUT_OF_BOUNDS_READ: {
        "groom_techniques": ["msg_msg_spray"],
        "leak_techniques": ["msg_msg_oob", "pipe_buffer_ops"],
        "primitives": ["msg_msg_primitive"],
        "escalation": [EscalationPath.COMMIT_CREDS],
    },
    BugClass.RACE_CONDITION: {
        "groom_techniques": ["dirty_cred_spray"],
        "leak_techniques": ["kallsyms", "pipe_buffer_ops"],
        "primitives": ["dirty_cred"],
        "escalation": [EscalationPath.DIRTY_CRED, EscalationPath.USMA],
    },
    BugClass.TYPE_CONFUSION: {
        "groom_techniques": ["msg_msg_spray"],
        "leak_techniques": ["pipe_buffer_ops"],
        "primitives": ["pipe_primitive"],
        "escalation": [EscalationPath.ROP_CHAIN],
    },
}

DEFAULT_STRATEGY = {
    "groom_techniques": ["msg_msg_spray"],
    "leak_techniques": ["kallsyms"],
    "primitives": ["simulation_only"],
    "escalation": [EscalationPath.UNKNOWN],
}


def select_strategy(bug_class: BugClass, fingerprint=None) -> dict:
    """Select exploitation strategy based on bug class and target info."""
    strategy = STRATEGY_MAP.get(bug_class, DEFAULT_STRATEGY)

    # If fingerprint is available, filter based on kernel capabilities
    if fingerprint:
        # If kallsyms is readable, prefer it
        if fingerprint.kallsyms_readable:
            strategy = dict(strategy)
            strategy["leak_techniques"] = ["kallsyms"] + [
                t for t in strategy["leak_techniques"] if t != "kallsyms"
            ]

    return strategy


# ---------------------------------------------------------------------------
# NVD API client
# ---------------------------------------------------------------------------

def fetch_nvd_cve(cve_id: str) -> Optional[dict]:
    """Fetch CVE data from NIST NVD API 2.0.

    Returns the raw CVE JSON or None on failure.
    """
    import urllib.request
    import urllib.error

    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    req = urllib.request.Request(url, headers={"Accept": "application/json"})

    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read())
            vulns = data.get("vulnerabilities", [])
            if vulns:
                return vulns[0].get("cve", {})
    except (urllib.error.URLError, urllib.error.HTTPError, json.JSONDecodeError):
        pass

    return None


def fetch_git_patch(commit_hash: str, repo_url: str = "") -> Optional[str]:
    """Fetch a git commit diff.

    If repo_url is provided, fetches from remote.  Otherwise tries
    to find it in a local linux kernel tree.
    """
    if repo_url:
        # Try fetching from git.kernel.org
        import urllib.request
        import urllib.error

        url = f"https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/patch/?id={commit_hash}"
        try:
            with urllib.request.urlopen(url, timeout=30) as resp:
                return resp.read().decode("utf-8", errors="replace")
        except (urllib.error.URLError, urllib.error.HTTPError):
            return None

    # Try local git repo
    try:
        result = subprocess.run(
            ["git", "show", "--format=%B", "--stat", commit_hash],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0:
            return result.stdout
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass

    return None


# ---------------------------------------------------------------------------
# Slab cache size estimation
# ---------------------------------------------------------------------------

# Common kernel object sizes for slab cache targeting
KNOWN_OBJECT_SIZES = {
    "nft_set_elem": 256,
    "sk_buff": 256,
    "msg_msg": 48,      # header only; total allocation depends on data size
    "pipe_buffer": 40,
    "struct cred": 192,
    "struct file": 256,
    "tty_struct": 736,
    "seq_operations": 32,
    "subprocess_info": 96,
    "timerfd_ctx": 256,
}


def estimate_slab_cache(obj_name: str, obj_size: int = 0) -> str:
    """Estimate which kmalloc slab cache an object falls into."""
    if obj_size == 0:
        obj_size = KNOWN_OBJECT_SIZES.get(obj_name, 0)

    if obj_size == 0:
        return "unknown"

    # kmalloc cache sizes: 8, 16, 32, 64, 96, 128, 192, 256, 512, 1024, ...
    caches = [8, 16, 32, 64, 96, 128, 192, 256, 512, 1024, 2048, 4096, 8192]
    for cache_size in caches:
        if obj_size <= cache_size:
            if cache_size >= 1024:
                return f"kmalloc-{cache_size // 1024}k"
            return f"kmalloc-{cache_size}"

    return "kmalloc-8k"


# ---------------------------------------------------------------------------
# Main analyzer
# ---------------------------------------------------------------------------

class VulnAnalyzer:
    """Main vulnerability analysis engine."""

    # ------------------------------------------------------------------
    # CVE Knowledge Base -- pre-configured exploit strategies for known CVEs
    #
    # Each entry maps a CVE to a complete ExploitPlan.  When the analyzer
    # encounters a known CVE, it skips NVD heuristics and uses this plan.
    # Unknown CVEs fall back to generic bug-class-based strategy selection.
    # ------------------------------------------------------------------

    KNOWN_CVES: dict[str, dict] = {
        "CVE-2026-23209": {
            "cve_id": "CVE-2026-23209",
            "cve_profile": "macvlan_uaf",
            "bug_class": BugClass.USE_AFTER_FREE,
            "subsystem": Subsystem.NETWORK_STACK,
            "affected_object": "macvlan_dev",
            "affected_slab_cache": "kmalloc-4k",
            "object_size": 2320,
            "groom_technique": "msg_msg_spray",
            "groom_cache": "kmalloc-4k",
            "trigger_method": "macvlan_netlink",
            "leak_technique": "kallsyms",
            "primary_primitive": "pcpu_stats",
            "escalation_path": EscalationPath.MODPROBE_PATH,
            "cleanup_method": "netlink_cleanup",
            "requires_namespaces": True,
            "requires_userfaultfd": False,
            "requires_io_uring": False,
            "requires_unprivileged_bpf": False,
            "spray_count": 256,
            "confidence": "high",
            "introduced_in": "4.9.1",
            "fixed_in": "6.12.70",
            "ubuntu_fixed": "6.8.0-104.104",
            "description": (
                "macvlan UAF: free_netdev() after failed register_netdevice() "
                "leaves stale macvlan_source_entry->vlan pointer. "
                "Packet receive path dereferences freed macvlan_dev, "
                "allowing pcpu_stats hijack for arbitrary kernel increment. "
                "Escalation via modprobe_path overwrite."
            ),
        },
        "CVE-2026-23412": {
            "cve_id": "CVE-2026-23412",
            "cve_profile": "netfilter_uaf",
            "bug_class": BugClass.USE_AFTER_FREE,
            "subsystem": Subsystem.NETFILTER,
            "affected_object": "nf_hook_entry",
            "affected_slab_cache": "kmalloc-128",
            "object_size": 128,
            "groom_technique": "msg_msg_spray",
            "groom_cache": "kmalloc-128",
            "trigger_method": "nfnetlink_hooks_dump",
            "leak_technique": "kallsyms",
            "primary_primitive": "msg_msg_primitive",
            "escalation_path": EscalationPath.MODPROBE_PATH,
            "cleanup_method": "safe_reset",
            "requires_namespaces": True,
            "requires_userfaultfd": False,
            "requires_io_uring": False,
            "requires_unprivileged_bpf": True,
            "spray_count": 256,
            "confidence": "medium",
            "introduced_in": "6.4.1",
            "fixed_in": "6.12.78",
            "ubuntu_fixed": "6.8.0-107",  # if exists, or later
            "description": (
                "netfilter BPF hook UAF: concurrent nfnetlink_hooks dump and "
                "hook modification leads to use-after-free on nf_hook_entry. "
                "Triggered via nfnetlink socket operations."
            ),
        },
    }

    def _lookup_known_cve(self, cve_id: str) -> ExploitPlan | None:
        """Check if this CVE has a pre-configured exploit strategy."""
        entry = self.KNOWN_CVES.get(cve_id.upper())
        if entry is None:
            return None

        plan = ExploitPlan(
            cve_id=entry.get("cve_id", cve_id),
            bug_class=entry["bug_class"],
            subsystem=entry["subsystem"],
            affected_object=entry.get("affected_object", ""),
            affected_slab_cache=entry.get("affected_slab_cache", ""),
            object_size=entry.get("object_size", 0),
            groom_technique=entry.get("groom_technique", ""),
            groom_cache=entry.get("groom_cache", ""),
            trigger_method=entry.get("trigger_method", ""),
            leak_technique=entry.get("leak_technique", ""),
            primary_primitive=entry.get("primary_primitive", ""),
            escalation_path=entry["escalation_path"],
            cleanup_method=entry.get("cleanup_method", ""),
            requires_namespaces=entry.get("requires_namespaces", False),
            requires_userfaultfd=entry.get("requires_userfaultfd", False),
            requires_io_uring=entry.get("requires_io_uring", False),
            requires_unprivileged_bpf=entry.get("requires_unprivileged_bpf", False),
            spray_count=entry.get("spray_count", 256),
            confidence=entry.get("confidence", "high"),
            description=entry.get("description", ""),
            introduced_in=entry.get("introduced_in", ""),
            fixed_in=entry.get("fixed_in", ""),
            ubuntu_fixed=entry.get("ubuntu_fixed", ""),
        )
        plan.cve_profile = entry.get("cve_profile", "generic")
        return plan

    def check_cve_applicable(self, cve_id: str, kernel_release: str) -> tuple[bool, str]:
        """Check if a CVE applies to a specific kernel release.

        Returns (is_vulnerable, reason_string).
        Uses the Ubuntu kernel version scheme: e.g. "6.8.0-106-generic"
        """
        entry = self.KNOWN_CVES.get(cve_id.upper())
        if entry is None:
            return True, "unknown CVE (no version data)"

        ubuntu_fixed = entry.get("ubuntu_fixed", "")
        if not ubuntu_fixed:
            return True, "no Ubuntu version data in knowledge base"

        # Extract Ubuntu kernel version for comparison
        # Format: "6.8.0-106-generic" or "6.8.0-106.106-generic"
        import re
        vm = re.match(r"(\d+\.\d+\.\d+)-(\d+)", kernel_release)
        if not vm:
            return True, f"cannot parse kernel version: {kernel_release}"

        base = vm.group(1)
        abi = int(vm.group(2))

        # Parse the fixed version
        fvm = re.match(r"(\d+\.\d+\.\d+)-(\d+)", ubuntu_fixed)
        if not fvm:
            return True, f"cannot parse fixed version: {ubuntu_fixed}"

        fbase = fvm.group(1)
        fabi = int(fvm.group(2))

        if base < fbase or (base == fbase and abi < fabi):
            return True, (
                f"kernel {kernel_release} is VULNERABLE "
                f"(fixed in {ubuntu_fixed})"
            )
        else:
            return False, (
                f"kernel {kernel_release} is PATCHED "
                f"(fix in {ubuntu_fixed})"
            )

    def analyze_cve(self, cve_id: str) -> ExploitPlan:
        """Analyze a CVE and produce an exploitation plan."""

        # First: check if we have a known strategy for this CVE
        known = self._lookup_known_cve(cve_id)
        if known is not None:
            return known

        plan = ExploitPlan(cve_id=cve_id)

        # Fetch CVE data from NVD
        cve_data = fetch_nvd_cve(cve_id)
        if cve_data:
            self._process_nvd_data(cve_data, plan)

        # If we have a commit hash from the CVE references, analyze the patch
        if plan.commit_hash:
            patch = fetch_git_patch(plan.commit_hash, repo_url="kernel.org")
            if patch:
                self._process_patch(patch, plan)

        # Select strategy based on what we know
        self._select_strategy(plan)

        return plan

    def analyze_commit(self, commit_hash: str) -> ExploitPlan:
        """Analyze a kernel git commit directly."""
        plan = ExploitPlan(commit_hash=commit_hash)

        patch = fetch_git_patch(commit_hash, repo_url="kernel.org")
        if patch:
            self._process_patch(patch, plan)

        self._select_strategy(plan)
        return plan

    def analyze_manual(
        self,
        bug_class: BugClass,
        subsystem: Subsystem,
        affected_object: str = "",
        object_size: int = 0,
        description: str = "",
    ) -> ExploitPlan:
        """Create a plan from manually-provided information."""
        plan = ExploitPlan(
            bug_class=bug_class,
            subsystem=subsystem,
            affected_object=affected_object,
            object_size=object_size,
            description=description,
        )

        if affected_object:
            plan.affected_slab_cache = estimate_slab_cache(
                affected_object, object_size
            )

        self._select_strategy(plan)
        return plan

    def _process_nvd_data(self, cve_data: dict, plan: ExploitPlan) -> None:
        """Extract information from NVD CVE data."""
        # Description
        descriptions = cve_data.get("descriptions", [])
        for desc in descriptions:
            if desc.get("lang") == "en":
                plan.description = desc.get("value", "")
                break

        # Detect bug class from description
        if plan.description:
            plan.bug_class = detect_bug_class(plan.description)

        # Look for kernel.org references for commit hashes
        refs = cve_data.get("references", [])
        for ref in refs:
            url = ref.get("url", "")
            # Look for git commit URLs
            commit_match = re.search(
                r"git\.kernel\.org.*commit.*[?&]id=([0-9a-f]{7,40})",
                url
            )
            if commit_match:
                plan.commit_hash = commit_match.group(1)
                break

            # Also check lore.kernel.org patch links
            commit_match = re.search(r"/([0-9a-f]{40})", url)
            if commit_match and "kernel" in url:
                plan.commit_hash = commit_match.group(1)
                break

    def _process_patch(self, patch: str, plan: ExploitPlan) -> None:
        """Extract information from a git patch."""
        # Detect bug class from commit message if not already known
        if plan.bug_class == BugClass.UNKNOWN:
            plan.bug_class = detect_bug_class(patch)

        # Detect subsystem from file paths in the diff
        file_paths = re.findall(r"^diff --git a/(.+?) b/", patch, re.MULTILINE)
        if not file_paths:
            # Try stat format
            file_paths = re.findall(r"^\s+(\S+\.c|\S+\.h)\s+\|", patch, re.MULTILINE)

        if file_paths:
            plan.subsystem = detect_subsystem(file_paths, patch)

        # Try to identify the affected object from the patch
        # Look for kfree, kmalloc, kzalloc calls with struct names
        alloc_match = re.search(
            r"k(?:m|z|c)alloc.*sizeof\(\*?(\w+)\)", patch
        )
        if alloc_match:
            plan.affected_object = alloc_match.group(1)

        free_match = re.search(r"kfree\((\w+)\)", patch)
        if free_match and not plan.affected_object:
            plan.affected_object = free_match.group(1)

    def _select_strategy(self, plan: ExploitPlan) -> None:
        """Select exploitation strategy based on the plan's bug class."""
        strategy = select_strategy(plan.bug_class)

        if strategy["groom_techniques"]:
            plan.groom_technique = strategy["groom_techniques"][0]
        if strategy["leak_techniques"]:
            plan.leak_technique = strategy["leak_techniques"][0]
        if strategy["primitives"]:
            plan.primary_primitive = strategy["primitives"][0]
        if strategy["escalation"]:
            plan.escalation_path = strategy["escalation"][0]

        # Estimate slab cache
        if plan.affected_object and not plan.affected_slab_cache:
            plan.affected_slab_cache = estimate_slab_cache(
                plan.affected_object, plan.object_size
            )

        # Set grooming cache to match the vulnerable object's cache
        if plan.affected_slab_cache:
            plan.groom_cache = plan.affected_slab_cache

        # Default spray count based on cache size
        if plan.spray_count == 0:
            plan.spray_count = 256  # conservative default

        # Set confidence
        if plan.bug_class != BugClass.UNKNOWN and plan.subsystem != Subsystem.OTHER:
            plan.confidence = "medium"
        if plan.affected_object and plan.affected_slab_cache != "unknown":
            plan.confidence = "high"

        # Cleanup method based on bug class
        if plan.bug_class in (BugClass.USE_AFTER_FREE, BugClass.DOUBLE_FREE):
            plan.cleanup_method = "slab_stabilize"
        elif plan.bug_class == BugClass.RACE_CONDITION:
            plan.cleanup_method = "thread_cleanup"
        else:
            plan.cleanup_method = "safe_reset"
