# Angband -- Automated Kernel Exploit Framework

**An open-source framework for automated kernel exploit generation -- accelerating CVE severity analysis so vendors, researchers, and the community can provide evidence to NIST/ENISA.**

The offensive side consistently outpaces the defensive side, especially in open-source projects like Linux. By automating exploit generation, Angband demonstrates real-world impact and provides concrete evidence for accurate CVE severity scoring, countering NIST's tendency to treat all CVEs as low severity by default.

## What Angband Does Today

Angband generates a working kernel exploit from its 7-stage pipeline and executes it inside an isolated QEMU guest to achieve **privilege escalation (uid=0)** from an unprivileged user. The entire process is automated and reproducible:

```bash
source venv/bin/activate
angband init demo                 # configure exploit scenario
angband generate                  # generate and compile C exploit
bash harness/setup.sh             # prepare QEMU VM (one-time)
bash harness/launch.sh            # boot VM
bash run_and_verify.sh            # deploy, execute, verify uid=0
```

### Demo Exploit Chain (vuln_drill CTF module)

The included `vuln_drill.ko` kernel module contains **real vulnerabilities** (modeled after [kernel-hack-drill](https://github.com/a13xp0p0v/kernel-hack-drill)). The generated exploit achieves privilege escalation through genuine exploitation techniques:

| Stage | Action | Technique |
|-------|--------|-----------|
| **Prep** | Open `/proc/vuln_drill_act`, pin CPU | Environment validation |
| **Groom** | `DRILL_ACT_ALLOC` | Allocate 95-byte object (kmalloc-96) containing `_printk` address |
| **Trigger** | `DRILL_ACT_FREE` | UAF: `kfree()` without nulling pointer |
| **Leak** | `DRILL_ACT_READ` offset 0 | Read `_printk` from freed object via UAF (KASLR bypass) |
| **Primitive** | `DRILL_ACT_WRITE` offset -8 | OOB write: overwrite `callback` field with `root_it()` |
| **Escalate** | `DRILL_ACT_CALLBACK` | Control flow hijack -> `commit_creds(prepare_kernel_cred(init_task))` |
| **Cleanup** | Close fds | uid=0 achieved |

**KASLR bypass**: The exploit leaks a kernel `.text` address (`_printk`) from the freed object's data area via UAF read, then computes `commit_creds`, `prepare_kernel_cred`, and `init_task` from fixed offsets embedded at code generation time. No `/proc/kallsyms`, no `sudo`, no hardcoded addresses.

**Verified output** (reproducible, 3/3 runs):
```
[+] uid=1000 euid=1000
[+] Leaked _printk      @ 0xffffffffXXXXXXXX
[+] KASLR bypass complete -- no kallsyms, no sudo
[+] PRIVILEGE ESCALATION SUCCESSFUL
[+]  uid=0  euid=0  gid=0  egid=0
[+] EXPLOIT COMPLETE -- got root!
```

## vuln_drill: CTF Kernel Module

The target module (`module/vuln_drill/`) provides `/proc/vuln_drill_act` with real exploitable bugs -- no backdoors, no magic ioctls:

| Bug | Code | Description |
|-----|------|-------------|
| **UAF** | `DRILL_ACT_FREE` | `kfree()` without nulling pointer in `items[]` |
| **UAF callback** | `DRILL_ACT_CALLBACK` | Calls `items[n]->callback()` without freed check |
| **OOB write** | `DRILL_ACT_WRITE` | Writes to `items[n]->data + offset` with no bounds check |
| **OOB read** | `DRILL_ACT_READ` | Reads from `items[n]->data + offset` with no bounds check |

See `module/vuln_drill/README.md` for full details and advanced exploit techniques.

## Setup

### Prerequisites

```bash
sudo apt-get install -y qemu-system-x86 cloud-image-utils python3 python3-venv gcc
```

### Install

```bash
git clone https://github.com/anthropics/angband.git
cd angband
python3 -m venv venv
source venv/bin/activate
pip install -e .
```

### Prepare QEMU Target

```bash
bash harness/setup.sh    # downloads Ubuntu 24.04 cloud image, creates overlay
bash harness/launch.sh   # boots VM with SMEP/SMAP disabled for basic exploit
```

The VM boots with `-cpu host,-smep,-smap` to allow the basic ret2usr exploit. For advanced exploits that bypass SMEP/SMAP, modify `harness/launch.sh`.

### Run the Exploit

```bash
angband init demo        # creates mordor_run/current/exploit.yaml
angband generate         # generates exploit.c, compiles exploit binary
bash run_and_verify.sh   # deploys to VM, runs, verifies uid=0
```

### Using Your Own VM

If you have an existing QEMU image:

```bash
bash harness/import.sh /path/to/your-vm.qcow2 2222 youruser
```

See `TESTING.md` for detailed instructions.

## Architecture

```
angband init demo
    |
    v
configs/ubuntu-24.04-x86_64.yaml   (symbol offsets, mitigations)
    |
    v
angband generate
    |
    +-- templates/exploit.c.jinja2  (exploit template with Jinja2)
    +-- symbol_offsets from config  (KASLR bypass constants)
    |
    v
mordor_run/current/exploit.c       (generated C source)
mordor_run/current/exploit          (compiled static binary)
    |
    v
run_and_verify.sh
    |
    +-- SSH into QEMU guest
    +-- Build & load vuln_drill.ko
    +-- Run exploit as unprivileged user
    +-- Collect dmesg + /proc/vuln_drill status
    +-- Verify uid=0
```

### Key Components

| Component | Purpose |
|-----------|---------|
| `angband/cli.py` | CLI commands: `init`, `generate`, `analyze`, `recon`, `pipeline` |
| `angband/generators/poc_gen.py` | Jinja2 template renderer, embeds symbol offsets |
| `angband/analysis/vuln_analyzer.py` | CVE-to-strategy engine (NVD API, bug classification) |
| `angband/recon/fingerprint.py` | Target kernel probing via SSH |
| `angband/leak/kaslr.py` | KASLR bypass technique library |
| `angband/primitives/registry.py` | Exploit primitive registry (12 techniques) |
| `angband/recon/slab.py` | Slab cache detection, RANDOM_KMALLOC_CACHES probe |
| `primitives/` | Reusable C exploit libraries (netlink, userns, kaslr, dirty_pagetable) |
| `module/vuln_drill/` | CTF kernel module with real UAF/OOB bugs + 4K alloc + kernel write |
| `templates/exploit.c.jinja2` | Exploit code template |
| `configs/` | Per-target kernel configs with symbol offsets |
| `harness/` | QEMU VM management (setup, launch, stop, reset, import) |

## CLI Reference

| Command | Description |
|---------|-------------|
| `angband init demo` | Initialize demo exploit scenario |
| `angband init CVE-2024-1086` | Analyze CVE, generate exploit config |
| `angband generate` | Generate C exploit from config, compile |
| `angband analyze CVE-2024-1086` | Analyze CVE without generating code |
| `angband recon` | Fingerprint QEMU guest kernel |
| `angband list-primitives` | List available exploit primitives (12 techniques) |
| `angband pipeline` | Run 7-stage pipeline (Python stages) |

## VM Lifecycle

| Action | Command |
|--------|---------|
| First-time setup | `bash harness/setup.sh` |
| Boot VM | `bash harness/launch.sh` |
| Stop VM | `bash harness/stop.sh` |
| Reset to clean state | `bash harness/reset.sh` |
| Import custom image | `bash harness/import.sh <image> [port] [user]` |
| Serial console | `bash harness/console.sh` |

## Success Criteria

A successful `run_and_verify.sh` run produces:

| Check | File | Expected |
|-------|------|----------|
| Privilege escalation | `exploit_run.log` | `PRIVILEGE ESCALATION SUCCESSFUL` |
| Root achieved | `exploit_run.log` | `uid=0 euid=0` |
| All 7 stages | `dmesg_tail.log` | `vuln_drill: stage <X> received` for each |
| Correct order | `vuln_drill_status.log` | `sequence_complete: yes` |
| KASLR bypassed | `exploit_run.log` | `Leaked _printk @ 0xffffffffXXXX` |

## Roadmap

### Completed
- [x] 7-stage pipeline with real privilege escalation (uid=0)
- [x] CTF kernel module with genuine UAF + OOB bugs (no backdoors)
- [x] Automatic KASLR bypass via infoleak (no kallsyms, no sudo)
- [x] Reproducible exploit generation (`angband generate` -> uid=0 every time)
- [x] CVE vulnerability analysis engine (NVD API, bug classification, version-range checking)
- [x] Target environment fingerprinting (kernel version, mitigations, slab state)
- [x] Exploit primitive library (12 techniques: msg_msg, pipe_buffer, setxattr, dirty_cred, modprobe_path, dirty_pagetable, commit_creds, netlink_ops, userns_setup, pcpu_stats, kallsyms_leak, kaslr_sidechannel)
- [x] QEMU isolation harness with overlay snapshots and instant reset
- [x] Custom VM image import (`harness/import.sh`)
- [x] Reusable C primitives auto-linked by `angband generate` (netlink, userns, KASLR, dirty_pagetable)
- [x] CVE knowledge base with pre-configured exploit strategies and per-kernel-version applicability
- [x] User + network namespace setup for CAP_NET_ADMIN exploitation
- [x] CONFIG_RANDOM_KMALLOC_CACHES detection and page-level bypass primitive (Dirty Pagetable)
- [x] KASLR bypass via kallsyms (parent namespace) + kcore ELF parsing for kernel memory reads

### In Progress
- [ ] CVE-2026-23209 (macvlan UAF) -- **analyzed and confirmed real** on kernel 6.8.0-101
  - UAF trigger works: `free_netdev()` after failed `register_netdevice()` leaves stale `macvlan_source_entry->vlan` pointer
  - Panic confirmed at `macvlan_forward_source+0x78` (CR2=0xb0, `vlan->dev = NULL` deref via IPv6 DAD workqueue)
  - `alloc_netdev_mqs → kvzalloc` path reclaims the freed slot (verified via dummy interface create/destroy)
  - **Blocker**: `CONFIG_RANDOM_KMALLOC_CACHES` (16-way randomized caches) prevents same-cache spray from userspace; needs Dirty Pagetable page-level bypass to complete the chain
  - Framework has ALL primitives needed (netlink ops, userns, KASLR leak, kcore ELF parsing, pcpu_stats write, Dirty Pagetable); just needs slab-drain + PTE-reclaim integration

### Next
- [ ] SMEP/SMAP bypass (ROP chain generation, kernel stack pivot)
- [ ] KPTI bypass (swapgs + trampoline return)
- [ ] Subsystem-specific trigger code (nf_tables, io_uring, bpf)
- [ ] Multi-kernel-version symbol offset database
- [ ] Full CVE-2026-23209 exploit chain: slab drain → PTE reclaim → pcpu_stats write → modprobe_path overwrite → init-ns root
- [ ] Additional CVE targets (CVE-2026-23412, CVE-2026-23340)
- [ ] Post-exploitation stability
- [ ] CVSS score evidence generation for NIST submissions

## License

GPL-3.0. See `LICENSE`.
