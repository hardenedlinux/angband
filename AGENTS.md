# Angband Agent Instructions

This document provides high-signal context for OpenCode agents working in the `angband` repository. It focuses on non-obvious setup requirements, expected workflows, and critical safety rules.

## Documentation Map

The `docs/` directory contains detailed reference material. **Start with `docs/index.md`** for the complete knowledge map, or consult individual docs directly:

| Document | Description |
|----------|-------------|
| `docs/index.md` | **START HERE** — Complete knowledge map organized by pipeline stage |
| `docs/CVE-2026-23209-analysis.md` | macvlan UAF — INCOMPLETE implementation (see status in doc) |
| `docs/CVE-2026-35555-analysis.md` | timerfd UAF analysis — why it's blocked by `list_del_rcu` |
| `docs/CVE-2026-44269-analysis.md` | perf UAF analysis — trigger stub, func ptr targets mapped |
| `docs/CVE-2026-33289-analysis.md` | io_uring UAF analysis — trigger stub, `io_task_work.func` target |
| `docs/bug-class-taxonomy.md` | 11 bug classes, PaX attack paradigms, SLUBStick, technique selection matrix |
| `docs/heap-exploitation.md` | SLUB internals, 6 spray methods, 5 escalation patterns, cross-cache mitigations |
| `docs/novel-techniques.md` | 13 cutting-edge techniques (LL_ATK, Kernel One Gadget, SLUBStick, CARDSHARK, etc.) |
| `docs/mitigations-defense.md` | VED/LKRG/AUTOSLAB mitigation taxonomy (consolidated in vkb.md) |
| `docs/manual_build.md` | Step-by-step guest VM exploitation walkthrough |
| `docs/vkb.md` | **Ring 0 exploitation reference index** — all external sources (papers, tools, CVEs) with URLs |
| `KERNEL_MITIGATIONS.md` | Verified kernel addresses, struct offsets, CVE patch status, sysctl requirements |
| `ARCHITECTURE.md` | Full architecture with data flow diagrams, strategy map, template docs |

### When to consult which doc

| Task | Start with |
|------|-----------|
| Analyzing a new CVE | `docs/index.md` → `docs/bug-class-taxonomy.md` |
| Choosing a spray/groom method | `docs/index.md` → `docs/heap-exploitation.md` → Spray Selection Guide |
| Selecting a technique for a blocker | `docs/index.md` → `docs/novel-techniques.md` → Technique Selection Matrix |
| Understanding a specific CVE | `docs/CVE-*-analysis.md` for that CVE |
| Getting kernel addresses for a target | `KERNEL_MITIGATIONS.md` → Verified Kernel Addresses |
| Understanding the template codegen | `ARCHITECTURE.md` → Jinja2 Templates section |
| Looking up an external paper/tool/CVE reference | `docs/vkb.md` → Quick Lookup |
| Understanding mitigations | `docs/vkb.md` → Defense & Mitigation Research |

## Core Architecture and Entrypoints
*   **Purpose**: Angband is an automated kernel exploit generation framework. Its goal is to produce full-chain kernel exploits from CVE identifiers to accelerate severity analysis. Currently, it generates staged demo payloads (simulation-only), runs them in an isolated QEMU guest, and verifies kernel-side stage evidence through the synthetic `vuln_drill` module. Real exploit generation is the next milestone.
*   **Entrypoint**: The main CLI tool is the installed `angband` command. Do not invoke repo-local scripts directly when the package entrypoint is available; install in editable mode and use `angband`.
*   **Structure**:
    *   Python package logic: `angband/`.
    *   C exploit reference primitives: `primitives/`.
    *   Generated runtime output: `mordor_run/current/exploit.yaml`, `mordor_run/current/exploit.c`, `mordor_run/current/exploit`.
    *   Synthetic testing module: `module/vuln_drill/`.

## Environment Setup
Agents should establish a clean Python environment from scratch to ensure predictable behavior, rather than assuming external dependencies exist.

1.  **Create and activate a virtual environment:**
    ```bash
    python3 -m venv venv
    source venv/bin/activate
    ```
2.  **Install the project in editable mode:**
    ```bash
    pip install -e .
    ```
    *This creates the `angband` entrypoint which correctly resolves module paths (e.g., `angband.core.engine`).*

## Test Execution & Safety Conventions
**CRITICAL**: The generated payload is currently non-operational (simulation-only), but the project goal is full-chain exploit generation. Always treat `mordor_run/current/exploit` as guest-only output. Never run it on the host machine.

### Kernel Mitigations
When testing exploits in the QEMU VM, certain kernel mitigations must be disabled. See `KERNEL_MITIGATIONS.md` for the complete list and commands.

Key sysctls to disable before exploit testing:
```bash
sudo sysctl -w kernel.perf_event_paranoid=-1
sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0
sudo sysctl -w kernel.kptr_restrict=0
```

1.  **Demo Execution Workflow**:
    *   The standard flow is to use `run_and_verify.sh`, which handles generation, QEMU interaction via SSH, and log extraction.
    *   In `angband init demo` mode, it also builds and loads `module/vuln_drill/vuln_drill.ko` in the guest.
    *   In `angband init <CVE>` mode, the CVE is metadata only and `run_and_verify.sh` skips guest kernel-module setup.
    ```bash
    # Assuming venv is active and QEMU harness is running in background
    ./run_and_verify.sh
    ```
2. **QEMU Harness Execution**:
    *   The harness is located in `harness/setup.sh`, `harness/launch.sh`, and `harness/stop.sh`. It requires `qemu-system-x86` and `cloud-image-utils` (`sudo apt install qemu-system-x86 cloud-image-utils`).
    *   Initialize the VM: `cd harness && ./setup.sh`
    *   Launch the VM: `./launch.sh`
    *   Connect to the Serial Console: `./console.sh` (useful if kernel panics and SSH drops)
    *   Stop the VM: `./stop.sh`
    *   The harness creates a 9p mount point, making the host's `angband` directory available inside the VM at `/mnt/angband`.

## Common Workflows & Commands
*   **Generating a Demo Configuration**:
    ```bash
    angband init <cve_or_commit> --target <target-name>
    ```
    *Examples*:
    *   `angband init demo --target ubuntu-24.04-x86_64`
    *   `angband init CVE-2024-1086 --target ubuntu-24.04-x86_64`
*   **Generating the C Payload**:
    ```bash
    angband generate
    ```
    *Note: This reads `mordor_run/current/exploit.yaml`, generates `mordor_run/current/exploit.c` using Jinja2 templates, and compiles `mordor_run/current/exploit`.*

## Modifying the Codebase
*   When editing Python code, test changes by regenerating the payload with `angband generate`.
*   When modifying C primitives (`primitives/*.c`), ensure the `angband generate` compilation step succeeds.
*   Demo verification artifacts are written under `mordor_run/current/`:
    *   `exploit_run.log`
    *   `dmesg_tail.log`
    *   `vuln_drill_status.log` in demo mode

## UAF Exploitation Analysis Framework

When analyzing UAF CVEs for privilege escalation potential, use this systematic approach.

For non-UAF bug classes (OOB write, double-free, type confusion, race conditions), first consult `docs/bug-class-taxonomy.md` for the appropriate exploitation approach.

### Step 1: Understand the Write Primitive
For each UAF, identify WHAT the kernel writes through the stale pointer:
- **Function pointers** → potential code execution (best)
- **Arbitrary data pointers** → potential arbitrary write (good)
- **Fixed offset writes** → limited exploitation (poor)
- **Fixed value writes** → requires chaining (poor)

### Step 2: Check Trigger Availability
- Can the write be triggered from unprivileged context?
- Does it require capabilities (CAP_SYS_TIME, CAP_NET_ADMIN, etc.)?
- Does it require specific kernel configs (e.g., CONFIG_USERFAULTFD)?

### Step 3: Find Function Pointer Dereference Paths
Key patterns to look for:
- `wake_up_locked_poll()` → `__wake_up_common()` → `entry->func(entry, ...)`
- `hrtimer_restart()` → `enqueue_hrtimer()` → callback on expiry
- `file_operations->read/write/ioctl` → indirect calls through vtable
- `timer_list.timer.function` → timer callbacks
- `call_rcu(func, ...)` → RCU callbacks

### Step 4: Map Object Layout for msg_msg Reclaim
When reclaiming via msg_msg spray, compute offset mapping:
```
struct freed_object {
    field_0  @ offset 0   → msg_msg.mtext[-hdr_len]
    field_1  @ offset N   → msg_msg.mtext[N - hdr_len]
    ...
}
msg_msg header ≈ 48 bytes (m_text starts at offset 48)
```

### Step 5: Exploitation Assessment Matrix

| Factor | Score | Assessment |
|--------|-------|------------|
| Write reaches function pointer | ★★★ | Direct code execution |
| Write reaches arbitrary address | ★★ | Needs 2-step (corrupt pointer → exec) |
| Write to fixed offset + controllable value | ★ | May be chainable |
| Write to fixed offset + fixed value | ✗ | Not exploitable alone |

### Template Conditional Structure (Jinja2)
The template uses `{% if %}` → `{% elif %}` chains where each `{% elif %}` implicitly closes the previous block:
```
{% if cve_profile == "macvlan_uaf" %}   ← opens
    ... stage code ...
{% elif cve_profile == "timerfd_uaf" %} ← closes previous if
    ...
{% elif groom_method == "msg_msg_spray" %} ← closes previous elif
    ...
{% endif %}                            ← closes entire chain
```
**CRITICAL**: `{% elif %}` blocks following `{% if %}` without `{% endif %}` between them ARE valid in Jinja2. The `{% elif %}` acts as both `{% endif %}` for the previous condition AND `{% if %}` for the new one. Always place CVE-specific sections BEFORE generic method-based sections.

### Verified CVE Exploitation Status

| CVE | Subsystem | Escalation | Key Target | Status | Analysis Doc |
|-----|-----------|-----------|------------|--------|-------------|
| CVE-2026-23209 | macvlan | modprobe_path | pcpu_stats corruption | WORKS - container escape context | `docs/CVE-2026-23209-analysis.md` |

**Note**: CVE-2026-23209 is for **container escape** (uid=0 in container → host root), NOT direct unprivileged privilege escalation. Requires `--privileged` container or CAP_SYS_ADMIN capability to create namespaces.

**Demo (vuln_drill)**: Works from uid=1000 directly via `/proc/vuln_drill` interface - true privilege escalation demo.

**Fake CVEs removed** (33289, 35555, 44269, 23412, 31431) - were hypothetical placeholders, not real vulnerabilities.

### Additional Reference Documentation

| Document | Purpose |
|----------|---------|
| `docs/bug-class-taxonomy.md` | Bug class classification, exploitation approaches, capability requirements, chain potential |
| `docs/heap-exploitation.md` | SLUB internals, 6 spray methods, 5 escalation patterns, naive vs SLUBStick cross-cache |
| `docs/novel-techniques.md` | 13 techniques: LL_ATK, Kernel One Gadget, SLUBStick, CARDSHARK, ExpRace, signalfd, etc. |

### Common Exploitation Pattern (All UAF CVEs)

```
Freed object → msg_msg reclaim (mtext@48) → controlled func ptr → kernel calls func(rdi=our_data)
                                                                          │
                                                              ┌───────────┴───────────┐
                                                      commit_creds (ROP chain)    modprobe_path (write + trigger)
```

For advanced technique alternatives (LL_ATK, Kernel One Gadget, signalfd credential overwrite), see `docs/novel-techniques.md`.
For spray method selection and slab internals, see `docs/heap-exploitation.md`.

### Verified Kernel Addresses (6.8.0-106-generic)

| Symbol | Address | Source |
|--------|---------|--------|
| commit_creds | `0xffffffff8e7472f0` | /proc/kallsyms (sudo) |
| prepare_kernel_cred | `0xffffffff8e747870` | /proc/kallsyms (sudo) |
| modprobe_path | `0xffffffff90dde440` | /proc/kallsyms (sudo) |
| init_task | `0xffffffff90c0fd40` | /proc/kallsyms (sudo) |

### Verified Struct Offsets (pahole, 6.8.0-106)

**timerfd_ctx** (216 bytes):
| Field | Offset | msg_msg mapping | Controllable? |
|-------|--------|-----------------|---------------|
| hrtimer.function | 40 | msg_msg.security | **No** (header) |
| hrtimer.base | 48 | mtext[0] | Yes |
| tintv | 120 | mtext[72] | Yes |
| wqh.lock | 136 | mtext[88] | Yes |
| wqh.head | 144 | mtext[96] | Yes |
| ticks | 160 | mtext[112] | Yes |
| expired | 172 | mtext[124] | Yes |

**msg_msg** (48 bytes header): m_list(0-15) + m_type(16-23) + m_ts(24-31) + next(32-39) + security(40-47) → **mtext starts at 48**

**wait_queue_head** (24 bytes): lock@0 + 4b hole + head@8(16b)
**wait_queue_entry** (40 bytes): flags@0 + private@8 + **func@16** + entry@24

### Reference Exploit: CVE-2026-23209 (macvlan)
**NOTE**: This exploit is INCOMPLETE. The analysis describes the technique but the implementation has gaps (see status in `docs/CVE-2026-23209-analysis.md`). Full analysis in that doc. Key technique:
1. msg_msg spray reclaims freed net_device
2. Fake macvlan_dev with pcpu_stats → modprobe_path - 8
3. Packet reception → u64_stats_inc writes to modprobe_path
4. modprobe trigger → root shell

Kernel mitigations checklist in: `KERNEL_MITIGATIONS.md`
Bug class taxonomy & techniques: `docs/bug-class-taxonomy.md`

## Exploitation Technique Reference

### msg_msg Spray (Primary Angband Primitive)
The most versatile heap spray in Linux kernel exploitation. Used by ALL angband CVEs.
Controllable size (48 to PAGE_SIZE), mtext overlays freed objects, corruptible fields
(m_ts/next/security) enable arbitrary read/free. See `docs/bug-class-taxonomy.md` for the full
PaX attack paradigm classification and SLUB allocator internals.

### Key Techniques Implemented in angband

| Technique | Where Used | CVE |
|-----------|-----------|-----|
| msg_msg reclaim → func ptr hijack | primitive stage | 35555, 44269, 33289 |
| wake_up_locked_poll exec | timerfd trigger | 35555 |
| pcpu_stats → modprobe_path write | macvlan primitive | 23209 |
| dirty_pagetable page reclaim | macvlan full | 23209 |
| commit_creds ROP chain | escalate stage (commit_creds path) | All |
| modprobe_path trigger | escalate stage (modprobe_path path) | All |
| KASLR side-channel bypass | leak stage | All |

### Modern Mitigations to Consider

| Mitigation | Effect on angband Exploits |
|-----------|---------------------------|
| CONFIG_RANDOM_KMALLOC_CACHES (v6.6) | Must slab drain + pattern spray (as done in macvlan) |
| Separate accounted caches (v5.14) | msg_msg and target object must match cache type |
| PaX AUTOSLAB | Same-type spray only; prefer dirty_pagetable for cross-cache |
| VED msg_msg integrity | Match object sizes exactly to bypass OOB check |
| kCFI/IBT | Data-only attacks preferred over ROP |
| CPU pinning restriction | Reduces spray reliability ~20-30% |

## Exploit Chaining / Vulnerability Pipelining

### Concept

A single UAF vulnerability often lacks a complete exploitation chain. Real-world exploits frequently **chain multiple CVEs** where:

- **CVE-A** provides a capability (e.g., info leak, CAP_SYS_TIME, KASLR bypass)
- **CVE-B** provides a primitive (e.g., limited write, heap control)
- **CVE-C** converts the primitive to privilege escalation

### Capability Model

Each exploit stage **provides** and **requires** capabilities:

| Capability | Provider | Consumer |
|-----------|----------|----------|
| `kaslr_bypass` | CVE-A leak stage | All CVEs that need kernel addresses |
| `cap_sys_time` | CVE with setuid/settimeofday | timerfd clock_was_set trigger |
| `cap_net_admin` | Namespace creation | macvlan netlink operations |
| `kernel_write_primitive` | CVE with pcpu_stats/msg_msg corruption | escalate stage |
| `kernel_read_primitive` | CVE with info leak | KASLR bypass, heap address leak |
| `heap_address` | Info leak from UAF residual data | Groom stage (precise reclaim) |
| `kallsyms_access` | kptr_restrict=0 or namespace bypass | Symbol resolution |
| `arbitrary_free` | Double-free CVE | Heap massage / reclaim |

### Pipeline Architecture (Proposed)

```
┌─────────────────────────────────────────────────────────────┐
│                    exploit_chain.yaml                        │
│  chain:                                                      │
│    - cve: CVE-2026-XXXX  # capability provider              │
│      provides: [cap_sys_time]                                │
│      output: { settime_capability: true }                    │
│    - cve: CVE-2026-35555 # primitive provider               │
│      requires: [cap_sys_time]                                │
│      provides: [kernel_write_primitive, wqh_control]         │
│      output: { write_target: "0xffff...." }                  │
│    - cve: CVE-2026-YYYY  # escalation (or built-in)         │
│      requires: [kernel_write_primitive]                      │
│      escalate: modprobe_path                                  │
└─────────────────────────────────────────────────────────────┘
```

### Data Flow Between Chained Exploits

```
  Stage(output) ──data──→ NextStage(input)
  
  Example: CVE-A leak → CVE-B primitive → CVE-C escalate
  
  kaslr_bypass output:  { kernel_base, modprobe_path_addr }
                         ↓
  primitive input:       { kernel_base, modprobe_path_addr }
  primitive output:      { corrupted_object_offset, write_value }
                         ↓
  escalate input:        { modprobe_path_addr, write_value }
  escalate output:       { root_shell }
```

### How to Add Chaining to the Framework

#### Step 1: Extend YAML Config

Add `requires` and `provides` to the exploit.yaml stages:

```yaml
stages:
  groom:
    method: "timerfd_spray"
    requires: []
    provides: [timerfd_handles, msg_msg_queues]
  trigger:
    method: "timerfd_cancel_circular" 
    requires: [timerfd_handles]
    provides: [uaf_condition, freed_ctx_count]
  leak:
    method: "kallsyms"
    requires: []
    provides: [kernel_base, modprobe_path_addr, kaslr_bypass]
  primitive:
    method: "timerfd_wqh_corruption"
    requires: [uaf_condition, kernel_base, msg_msg_queues]
    provides: [kernel_write_primitive, corrupted_wqh]
  escalate:
    method: "modprobe_path"
    requires: [kernel_write_primitive, modprobe_path_addr]
    provides: [root_shell]
```

#### Step 2: Add Capability Checker

```python
# angband/chaining/capabilities.py
class CapabilityChecker:
    def check(self, capability, context):
        """Check if a capability is available from prior stages"""
        if capability == "kaslr_bypass":
            return context.get("kernel_base") is not None
        if capability == "cap_sys_time":
            return context.get("has_settime_cap", False)
        ...
    
    def can_execute_stage(self, stage_config, context):
        for req in stage_config.get("requires", []):
            if not self.check(req, context):
                return False, f"Missing: {req}"
        return True, "OK"
```

#### Step 3: Add Pipeline Orchestrator

```python
# angband/chaining/orchestrator.py
class ExploitChain:
    def __init__(self, chain_config):
        self.cves = chain_config["chain"]
        self.context = {}  # shared state between CVEs
    
    def execute(self):
        for cve_step in self.cves:
            cve_id = cve_step["cve"]
            # 1. Generate exploit for this CVE
            config = analyze_and_generate(cve_id, self.context)
            # 2. Run the exploit (in QEMU)
            result = run_in_qemu(config)
            # 3. Extract outputs and add to shared context
            self.context.update(result.get("output", {}))
            # 4. Check if escalation achieved
            if result.get("uid") == 0:
                return True, "ROOT"
        return False, "Chain incomplete"
```

#### Step 4: Template Fragmentation

Split the monolithic template into composable fragments:

```
templates/stages/
  groom/
    macvlan_uaf.c.jinja2
    timerfd_uaf.c.jinja2
    io_uring_uaf.c.jinja2
    perf_ring_uaf.c.jinja2
    generic_msg_msg.c.jinja2
  trigger/
    macvlan_uaf.c.jinja2
    timerfd_uaf.c.jinja2
    generic_uaf.c.jinja2
  leak/
    macvlan_uaf.c.jinja2
    kallsyms_parent.c.jinja2
    sidechannel.c.jinja2
  primitive/
    macvlan_uaf.c.jinja2
    timerfd_uaf.c.jinja2
    generic_msg_msg.c.jinja2
  escalate/
    modprobe_path.c.jinja2
    commit_creds.c.jinja2
    dirty_cred.c.jinja2
```

The generator composes: `groom(timerfd) + trigger(timerfd) + leak(kallsyms) + primitive(timerfd) + escalate(modprobe)`

### Practical Example: timerfd exploit chain

The analysis showed CVE-2026-35555 needs `CAP_SYS_TIME` to trigger `clock_was_set()`. A complete chain would be:

```
Step 1: CVE-with-CAP_SYS_TIME-provider
  → Gains CAP_SYS_TIME capability (via setuid binary bugs, namespace tricks, etc.)
  → Or uses a CVE that directly triggers settimeofday() without capabilities
  
Step 2: CVE-2026-35555 (timerfd UAF)
  → Uses CAP_SYS_TIME to call settimeofday() → triggers clock_was_set()
  → clock_was_set writes to freed timerfd_ctx (reclaimed by msg_msg)
  → msg_msg contains fake wqh → wake_up_locked_poll → func pointer call
  → Achieves kernel code execution
  
Step 3: Escalation
  → Use kernel code execution to call commit_creds(prepare_kernel_cred(0))
  → Or overwrite modprobe_path and trigger
```

### Chaining Decision Tree

```
Can the exploit achieve escalation alone?
  ├── YES → Single CVE exploit (e.g., CVE-2026-23209)
  └── NO  → What is missing?
       ├── Missing capability (e.g., CAP_SYS_TIME)?
       │   └── Find CVE that provides it → CHAIN
       ├── Missing write primitive?
       │   └── Find CVE with OOB/UAF write → CHAIN  
       ├── Missing info leak?
       │   └── Find CVE with infoleak → CHAIN
       └── Fixed-offset/fixed-value writes only?
           └── Can we corrupt something that later yields exec?
               ├── YES → Deferred exploitation (complex chain)
               └── NO  → NOT exploitable with current CVEs
```

### Implementation Priority

| Priority | Item | Effort |
|----------|------|--------|
| P0 | Add `requires`/`provides` to YAML schema | Low |
| P0 | Capability checker module | Medium |
| P1 | Pipeline orchestrator for multi-CVE chains | High |
| P1 | Template fragmentation into per-stage files | High |
| P2 | Shared context data passing between CVEs | Medium |
| P2 | Fallback/retry logic for failed stages | Medium |
| P3 | Automated CVE pairing (find complementary CVEs) | Very High |
| P3 | Chain verification in QEMU (multi-CVE execution) | Very High |
