# Angband Agent Instructions

This document provides high-signal context for OpenCode agents working in the `angband` repository. It focuses on non-obvious setup requirements, expected workflows, and critical safety rules.

## Documentation Map

The `docs/` directory contains detailed reference material. **Start with `docs/index.md`** for the complete knowledge map, or consult individual docs directly:

| Document | Description |
|----------|-------------|
| `docs/index.md` | **START HERE** — Complete knowledge map organized by pipeline stage |
| `docs/bug-class-taxonomy.md` | 11 bug classes, PaX attack paradigms, SLUBStick, technique selection matrix |
| `docs/heap-exploitation.md` | SLUB internals, 6 spray methods, 5 escalation patterns, cross-cache mitigations |
| `docs/novel-techniques.md` | 13 cutting-edge techniques (LL_ATK, Kernel One Gadget, SLUBStick, CARDSHARK, etc.) |
| `docs/mitigations-defense.md` | VED/LKRG/AUTOSLAB mitigation taxonomy (consolidated in vkb.md) |
| `docs/manual_build.md` | Step-by-step guest VM exploitation walkthrough |
| `docs/vkb.md` | **Ring 0 exploitation reference index** — all external sources (papers, tools, CVEs) with URLs |
| `KERNEL_MITIGATIONS.md` | Verified kernel addresses, struct offsets, CVE patch status, sysctl requirements |
| `ARCHITECTURE.md` | Full architecture with data flow diagrams, strategy map, template docs |
| `TESTING.md` | End-to-end testing guide: prerequisites, demo/CVE test steps, success criteria, troubleshooting |

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
| Running end-to-end tests | `TESTING.md` → Step-by-step instructions |

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


### Step 5: Exploitation Assessment Matrix

| Factor | Score | Assessment |
|--------|-------|------------|
| Write reaches function pointer | ★★★ | Direct code execution |
| Write reaches arbitrary address | ★★ | Needs 2-step (corrupt pointer → exec) |
| Write to fixed offset + controllable value | ★ | May be chainable |
| Write to fixed offset + fixed value | ✗ | Not exploitable alone |


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

#### Step 2: Add Capability Checker

#### Step 3: Add Pipeline Orchestrator

#### Step 4: Template Fragmentation

The generator composes: `groom(timerfd) + trigger(timerfd) + leak(kallsyms) + primitive(timerfd) + escalate(modprobe)`

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
