# Angband Architecture

Deep-dive into Angband's internals for contributors and developers.
For setup and usage, see `README.md`.

## Workflow Overview

```
                              ANGBAND WORKFLOW
 ============================================================================

 PHASE 1: ENVIRONMENT SETUP (one-time)
 ──────────────────────────────────────

   python3 -m venv venv        pip install -e .        harness/setup.sh
         │                          │                        │
         v                          v                        v
     [venv created]          [angband CLI ready]    [Download cloud image]
                                                    [Generate SSH keys ]
                                                    [Create seed.img   ]
                                                    [Create disk.qcow2 ]
                                                             │
                                                             v
                                                      harness/launch.sh
                                                             │
                                                             v
                                                    ┌─────────────────┐
                                                    │   QEMU VM       │
                                                    │  (port 2222)    │
                                                    │  9p:/mnt/angband│
                                                    └─────────────────┘

 PHASE 2: INIT
 ─────────────

   angband init <arg> --target <target>
         │
         ├── arg == "demo"?
         │       │
         │   ┌───┴────YES──────────────────┐    ┌────NO──────────────────────┐
         │   │  Load target config YAML    │    │  VulnAnalyzer              │
         │   │  configs/ubuntu-24.04-*.yaml│    │    │                       │
         │   │        │                    │    │    ├─ Fetch NVD API        │
         │   │        v                    │    │    ├─ Detect bug class     │
         │   │  mode: "demo"               │    │    ├─ Detect subsystem     │
         │   │  kernel_target: "vuln_drill" │    │    ├─ Fetch git patch      │
         │   │  demo_profile: "vuln_drill" │    │    ├─ Select strategy      │
         │   │  symbol_offsets: {...}       │    │    v                       │
         │   │  stage methods from config  │    │  mode: "exploit"           │
         │   └─────────────┬───────────────┘    │  ExploitPlan -> config     │
         │                 │                    └──────────┬──────────────────┘
         │                 │                               │
         │                 └──────────┬────────────────────┘
         │                            │ (fallback to demo on error)
         v                            v
              mordor_run/current/exploit.yaml


 PHASE 3: GENERATE
 ─────────────────

   angband generate
         │
         v
   Read exploit.yaml
         │
         ├── mode == "demo"?
         │       │
         │   YES─┤                       NO─┐
         │       v                          v
         │  exploit.c.jinja2       exploit_real.c.jinja2
         │       │                          │
         │       └──────────┬───────────────┘
         │                  │
         │                  v
         │         Jinja2 render with config
         │         (symbol_offsets, stage methods,
         │          bug_class, subsystem, etc.)
         │                  │
         │                  v
         │     mordor_run/current/exploit.c
         │                  │
         │                  v
         │     gcc -Wall -Wextra -static
         │                  │
         │                  v
         │     mordor_run/current/exploit  (static binary)


 PHASE 4: RUN & VERIFY  (run_and_verify.sh)
 ───────────────────────

   run_and_verify.sh
         │
         ├─ Read kernel_target from exploit.yaml
         ├─ Run angband generate
         ├─ Wait for VM (SSH poll)
         │
         ├── kernel_target == "vuln_drill"?
         │         │
         │     YES─┤                                      NO─┐
         │         v                                         v
         │   ┌──────────────────────────────┐   ┌────────────────────────┐
         │   │  SSH into guest:             │   │  SSH into guest:       │
         │   │  1. Mount 9p /mnt/angband    │   │  1. Mount 9p           │
         │   │  2. apt install build tools  │   │  2. Run ./exploit      │
         │   │  3. Build vuln_drill.ko      │   │                        │
         │   │  4. insmod vuln_drill.ko     │   └───────────┬────────────┘
         │   │  5. Disable kptr_restrict    │               │
         │   │  6. Run ./exploit            │               │
         │   └──────────────┬───────────────┘               │
         │                  │                               │
         │                  v                               v
         │        ┌─────────────────────┐         ┌──────────────────┐
         │        │  Collect logs:      │         │  Collect logs:   │
         │        │  exploit_run.log    │         │  exploit_run.log │
         │        │  dmesg_tail.log     │         │  dmesg_tail.log  │
         │        │  vuln_drill_status  │         └────────┬─────────┘
         │        └─────────┬───────────┘                  │
         │                  │                              │
         │                  v                              v
         │   ┌──────────────────────────────┐   ┌──────────────────────┐
         │   │  VERIFY (demo):             │   │  VERIFY (CVE):       │
         │   │  - "DEMO COMPLETE"          │   │  - "EXPLOIT COMPLETE"│
         │   │  - "PRIVILEGE ESCALATION    │   │  - "PRIVILEGE        │
         │   │     SUCCESSFUL"             │   │     ESCALATION       │
         │   │  - 7 stage markers in dmesg │   │     SUCCESSFUL"     │
         │   │  - sequence_complete: yes   │   │                      │
         │   │  - out_of_order: no         │   └──────────────────────┘
         │   └──────────────────────────────┘


 PHASE 5: CLEANUP
 ────────────────

   harness/stop.sh ──> Kill QEMU
   harness/reset.sh ──> Fresh overlay from base image
   cleanup.sh ──> Remove mordor_run/ runtime state
   cleanup.sh --all ──> Also remove cached cloud image
   cleanup.sh --nuke ──> Remove everything including venv
```

## Demo Exploit Chain

When running in demo mode against the `vuln_drill` kernel module, the
generated exploit executes a 7-stage chain inside the QEMU guest:

```
   ┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐
   │  PREP    │───>│  GROOM   │───>│ TRIGGER  │───>│  LEAK    │
   │          │    │          │    │          │    │          │
   │ Open     │    │ Alloc    │    │ Free     │    │ Read     │
   │ /proc/   │    │ drill_   │    │ item     │    │ _printk  │
   │ vuln_    │    │ item     │    │ (UAF)    │    │ addr from│
   │ drill_act│    │ (kmalloc │    │ ptr not  │    │ freed    │
   │          │    │  -96)    │    │ nulled   │    │ memory   │
   └──────────┘    └──────────┘    └──────────┘    └──────────┘
                                                        │
         ┌──────────────────────────────────────────────┘
         │    Compute commit_creds, prepare_kernel_cred,
         │    init_task from leaked _printk + offsets
         v
   ┌──────────┐    ┌──────────┐    ┌──────────┐
   │PRIMITIVE │───>│ ESCALATE │───>│ CLEANUP  │
   │          │    │          │    │          │
   │ OOB write│    │ Invoke   │    │ Close    │
   │ at off   │    │ hijacked │    │ file     │
   │ -8 to    │    │ callback │    │ descs    │
   │ overwrite│    │ -> calls │    │          │
   │ callback │    │ root_it()│    │          │
   │ with     │    │ uid=0!   │    │          │
   │ root_it  │    │          │    │          │
   └──────────┘    └──────────┘    └──────────┘
```

### drill_item_t Memory Layout

The `vuln_drill` module allocates 95-byte objects in `kmalloc-96`:

```
   struct drill_item_t (95 bytes)
   ┌────────────────────────────────────────────────┐
   │ offset 0:  foobar     (8 bytes, canary)        │
   │ offset 8:  callback   (8 bytes, fn pointer)    │ <-- OOB write target
   │ offset 16: data[79]   (79 bytes)               │
   │            data[0..7] = _printk address         │ <-- KASLR leak source
   └────────────────────────────────────────────────┘

   OOB write at data offset -8 reaches the callback field.
   DRILL_ACT_CALLBACK invokes item->callback() for control flow hijack.
```

## Data Flow

```
   configs/*.yaml ──┐
                     ├──> angband init ──> exploit.yaml
   CVE / "demo" ────┘                         │
                                               v
   templates/*.jinja2 ──> angband generate ──> exploit.c ──> exploit
                                                                │
                                                                v
                               run_and_verify.sh ──> QEMU Guest (SSH+9p)
                                      │                    │
                                      v                    v
                               exploit_run.log      dmesg_tail.log
                               vuln_drill_status.log (demo only)
                                      │
                                      v
                               Verification Pass/Fail
```

## Directory Structure

```
angband/
├── angband/                    # Python package (installed as 'angband' CLI)
│   ├── cli.py                  # Click CLI: init, generate, analyze, recon, pipeline
│   ├── runtime.py              # mordor_run/ path resolution
│   ├── core/
│   │   └── engine.py           # StageEngine: 7-stage pipeline orchestrator
│   ├── generators/
│   │   └── poc_gen.py          # Jinja2 template renderer + gcc compiler
│   ├── stages/                 # Python stage implementations
│   │   ├── common.py           # describe(), notify_vuln_drill()
│   │   ├── prep.py, groom.py, trigger.py, leak.py
│   │   ├── primitive.py, escalate.py, cleanup.py
│   ├── analysis/
│   │   └── vuln_analyzer.py    # CVE analysis: NVD fetch, bug classification
│   ├── primitives/
│   │   └── registry.py         # Exploit primitive library (7 techniques)
│   ├── recon/
│   │   └── fingerprint.py      # QEMU guest kernel fingerprinting
│   └── leak/
│       └── kaslr.py            # KASLR bypass techniques (3 methods)
├── configs/                    # Per-target kernel configs
│   ├── ubuntu-24.04-x86_64.yaml
│   └── ubuntu-26.04-x86_64.yaml
├── templates/                  # Jinja2 C code templates
│   ├── exploit.c.jinja2        # Demo mode (vuln_drill exploit)
│   └── exploit_real.c.jinja2   # Real CVE mode (scaffolded)
├── primitives/                 # C reference implementations
│   ├── msg_msg.c/h, pipe_buffer.c/h, dirty_cred.c/h
├── module/vuln_drill/          # Synthetic vulnerable kernel module
│   ├── vuln_drill.c, drill.h, Makefile
├── harness/                    # QEMU VM lifecycle
│   ├── setup.sh                # One-time: download image, gen keys, create overlay
│   ├── launch.sh               # Boot VM (KVM or emulation, SSH on 2222)
│   ├── stop.sh                 # Kill VM
│   ├── reset.sh                # Fresh overlay, re-run cloud-init
│   ├── console.sh              # Serial console (telnet :4444)
│   └── import.sh               # Import custom QEMU image
├── run_and_verify.sh           # End-to-end orchestration + verification
├── cleanup.sh                  # Runtime cleanup (3 levels)
└── mordor_run/                 # Runtime output (gitignored)
    ├── current/                # exploit.yaml, exploit.c, exploit, logs
    ├── harness/                # disk.qcow2, seed.img, qemu.pid
    ├── cache/                  # Base cloud image (cached)
    └── ssh/                    # SSH key pair for guest access
```

## QEMU Harness

The harness provides an isolated execution environment:

```
   ┌─────────────────────────────────────────────────────────────┐
   │  HOST                                                       │
   │                                                             │
   │  mordor_run/current/exploit ──(9p mount)──┐                │
   │                                            │                │
   │  SSH (port 2222) ─────────────────────────┐│                │
   │                                           ││                │
   │  ┌────────────────────────────────────────┼┼──────────────┐ │
   │  │  QEMU GUEST                            ││              │ │
   │  │                                        ││              │ │
   │  │  /mnt/angband ◄────────────────────────┘│              │ │
   │  │       │                                  │              │ │
   │  │       ├── mordor_run/current/exploit     │              │ │
   │  │       └── module/vuln_drill/             │              │ │
   │  │                                          │              │ │
   │  │  ubuntu@localhost ◄──────────────────────┘              │ │
   │  │       │                                                 │ │
   │  │       ├── insmod vuln_drill.ko  (demo mode)            │ │
   │  │       └── ./exploit             (unprivileged)         │ │
   │  │                                                         │ │
   │  │  Ports: SSH=22, Serial=4444, GDB=1234                  │ │
   │  │  CPU: host,-smep,-smap (KVM) or qemu64,-smep,-smap    │ │
   │  │  RAM: 4GB, CPUs: 2                                     │ │
   │  └─────────────────────────────────────────────────────────┘ │
   └─────────────────────────────────────────────────────────────┘
```

### VM Lifecycle

| Action | Command | What It Does |
|--------|---------|--------------|
| Setup | `harness/setup.sh` | Download base image, gen SSH keys, create overlay + seed |
| Boot | `harness/launch.sh` | Start QEMU in background, wait for SSH |
| Stop | `harness/stop.sh` | Graceful shutdown, then SIGKILL if needed |
| Reset | `harness/reset.sh` | Delete overlay, recreate from base (instant) |
| Console | `harness/console.sh` | `telnet localhost 4444` for serial access |
| Import | `harness/import.sh` | Use a custom VM image |

## CVE Analysis Pipeline

When `angband init CVE-XXXX-YYYY` is invoked, the `VulnAnalyzer` attempts
to produce an exploitation strategy automatically:

```
   CVE ID
     │
     v
   Fetch from NVD API 2.0
     │
     ├── Extract description
     │     │
     │     v
     │   Regex-based bug class detection
     │   (UAF, double-free, OOB, race, type confusion, ...)
     │
     ├── Extract references
     │     │
     │     v
     │   Find git.kernel.org commit URL
     │     │
     │     v
     │   Fetch git patch
     │     │
     │     v
     │   Detect subsystem from file paths
     │   (netfilter, nftables, io_uring, bpf, mm, ...)
     │     │
     │     v
     │   Estimate affected object + slab cache
     │
     └──> Select exploitation strategy from STRATEGY_MAP
            │
            v
          ExploitPlan
            │
            v
          exploit.yaml (mode: "exploit")
```

### Strategy Map (bug class -> stage method selection)

| Bug Class | Groom | Trigger | Leak | Primitive | Escalate |
|-----------|-------|---------|------|----------|---------|
| UAF (hash stale) | slab drain + msg_msg spray | invalid name → free_netdev | kallsyms | PTE dirty pagetable → pcpu_stats | modprobe_path |
| UAF (list-based) | msg_msg spray | close race → kfree_rcu | kallsyms | msg_msg reclaim → func ptr hijack | commit_creds / modprobe_path |
| OOB write | msg_msg / setxattr spray | trigger condition | kallsyms | corrupt adjacent object | modprobe_path / commit_creds |
| Double-free | msg_msg spray | double-free trigger | kallsyms | freelist corruption → obj conf | commit_creds / modprobe_path |
| Race condition | dirty_cred spray | concurrent ops race | kallsyms | list corruption → LL_ATK | commit_creds |

Note: `dirty_pagetable` is a **primitive** technique (provides arbitrary kernel write), not an escalate technique. The modprobe_path trigger is the escalate step after the write primitive is established.

## Jinja2 Templates

### Demo Template (`exploit.c.jinja2`)

Generates a complete, functional exploit against `vuln_drill.ko`. The template
embeds `symbol_offsets` from the config as C `#define` constants at code
generation time. If offsets are missing, compilation fails with `#error`.

### Real Template (`exploit_real.c.jinja2`)

Generates exploit code for real CVEs. Uses Jinja2 conditionals to select
the appropriate C code for each stage:

| Stage | Config Key | Options |
|-------|-----------|---------|
| Groom | `groom_method` | `msg_msg_spray`, `pipe_buffer_spray`, `slab_drain`, `pattern_spray` |
| Trigger | `bug_type` | `use_after_free`, `double_free`, `oob_write`, `oob_read` |
| Leak | `leak_method` | `kallsyms`, `kallsyms_parent`, `sidechannel`, `msg_msg_oob` |
| Primitive | `primitive_method` | `pcpu_stats_corrupt`, `msg_msg_reclaim`, `pipe_primitive`, `dirty_pagetable` |
| Escalate | `escalate_method` | `modprobe_path`, `commit_creds`, `dirty_cred`, `signalfd_cred` |

Note: `dirty_pagetable` is listed as an escalate option but is actually a **primitive** (write-enabler). In CVE-2026-23209, `dirty_pagetable` enables the write in the primitive stage; `modprobe_path` is the escalate step.

Most real-mode code paths are scaffolded but not yet functional.
