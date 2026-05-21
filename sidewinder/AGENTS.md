# Sidewinder Agent Instructions

This document provides high-signal context for OpenCode agents working in the `sidewinder` repository. It covers setup, architecture, safety rules, and expected workflows.

## Purpose
**sidewinder** is a userland-only toolkit for hunting CPU side-channel vulnerabilities and DRAM Rowhammer vulnerabilities. It detects, probes, and exploits microarchitectural attacks without kernel modules or eBPF. Target: x86_64 Linux.

## Architecture

```
sidewinder/
├── pyproject.toml                  # pip install -e .
├── cleanup.sh                      # Kills processes, releases huge pages, cleans artifacts
├── c_primitives/                   # Native C shared library (libsidewinder.so)
│   ├── cache.c                     # Flush+Reload, Prime+Probe, cache calibration
│   ├── timer.c                     # RDTSC/RDTSCP timing, CPU pinning
│   ├── memory.c                    # Huge pages, pagemap, CPUID cache topology
│   ├── hammer.c                    # Blacksmith frequency-based hammer patterns
│   ├── tsa_probe.c                 # TSA, GhostRace, BHI, prefetch KASLR probes
│   ├── exploit_verify.c            # Flush+Reload spy, PTE flip, modprobe escalation
│   ├── sidewinder.h                # Shared header with all C API declarations
│   └── Makefile                    # gcc -O3 -march=native, outputs libsidewinder.so
├── src/sidewinder/
│   ├── cli.py                      # Click CLI: detect, probe, exploit, auto, report
│   ├── detector/{cpu,mitigation,dram,profile}.py
│   ├── probe/{cache_side,speculative,rowhammer,dram_re}.py
│   ├── exploit/{kaslr,cred_leak,pte_flip,vmscape}.py
│   ├── primitives/native.py        # ctypes bindings for libsidewinder.so
│   ├── report/reporter.py          # JSON and Markdown report generation
│   └── utils/system.py             # /proc, /sys, CPUID helpers, shared library finder
└── profiles/{cpu,dram}/            # Future: per-architecture profile data (JSON)
```

**Data flow:**
```
CPUID + /sys/vulnerabilities  →  detector/cpu.py  →  profile.py  →  report
        │
        ├── probe/cache_side.py  →  calibration, FR/PP viability
        ├── probe/speculative.py  →  Spectre/Meltdown/Zenbleed/Downfall/TSA/GhostRace/BHI tests
        ├── probe/rowhammer.py  →  Blacksmith frequency-based fuzzer
        └── probe/dram_re.py  →  DRAMA-style address function reverse engineering
                │
                ├── exploit/kaslr.py  →  kallsyms or AMD prefetch side-channel KASLR bypass
                ├── exploit/cred_leak.py  →  info leak via TSA (host-safe on AMD Zen 3/4)
                ├── exploit/verify.py  →  Flush+Reload spy (spy-leak command)
                ├── exploit/pte_flip.py  →  PTE flip escalation (VM-only, gated)
                └── exploit/vmscape.py  →  VM-to-Host leak probes (VMScape, L1TF, MDS)
```

## Environment Setup
1. **Create and activate a virtual environment:**
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```
2. **Build the C primitives:**
   ```bash
   make -C c_primitives
   ```
3. **Install the Python package:**
   ```bash
   pip install -e .
   ```
   This creates the `sidewinder` entrypoint.

## Safety & Exploitation Rules (CRITICAL)

### Two Scenarios
| Scenario | Detection | Probing | Info Leak | Write Exploitation |
|----------|-----------|---------|-----------|--------------------|
| `--scenario host` | Yes | Yes | Yes | **NEVER** |
| `--scenario vm` | Yes | Yes | Yes | Yes (PTE flip, escalation) |

### Hard Rules
- **`--scenario host`**: ZERO writes to system state. No PTE flips. No kernel memory writes. No process credential modification. Detection + probe + info leak only.
- **`--scenario vm`**: Full exploitation permitted. Requires `--scenario vm` flag AND user confirmation at runtime. Exploit writes to kernel memory via DRAM bit flips.
- **Never run `exploit/exploit`** on the host machine. The generated exploit binary is for VM guests only.
- **Rowhammer hammering** (`probe rowhammer`) is safe to run anywhere — it only flips bits in its own allocated DRAM pages and checks for corruption. But it can cause system instability if hammering is too aggressive.

### Cleanup
If the tool leaves lingering processes or huge page allocations, run:
```bash
bash cleanup.sh
```
This kills any sidewinder processes, releases huge pages, unmounts hugetlbfs, cleans temp files, and restores CPU governor.

## Common Workflows

### Detection
```bash
sidewinder detect                     # Full system scan (CPU + DRAM + CVEs)
sidewinder detect --cpu               # CPU-only
sidewinder detect --dram              # DRAM-only
sidewinder detect --json              # JSON output
sidewinder detect --output report.md  # Write to file
```

### Probing
```bash
sidewinder probe side-channel         # Flush+Reload, Prime+Probe calibration
sidewinder probe speculative          # Spectre v1, Meltdown, Zenbleed, Downfall, TSA, GhostRace, BHI, SSB tests
sidewinder probe hertzbleed          # Hertzbleed DVFS timing side-channel (CVE-2022-23823)
sidewinder probe zenhammer           # ZenHammer AMD Zen DDR5 Rowhammer (2024)
sidewinder probe rowhammer --time 60  # 60-minute Blacksmith-style fuzzing
```

### Exploitation
```bash
sidewinder exploit kaslr                  # KASLR bypass (host-safe)
sidewinder exploit credential-leak        # Info leak via TSA/Meltdown (host-safe)
sidewinder exploit spy-leak               # Flush+Reload spy: leak victim file via cache side-channel
sidewinder exploit vmscape                # VM-to-Host leak (VMScape, L1TF, MDS) - host-safe info leak
sidewinder exploit rowhammer-escalation --scenario vm  # Privilege escalation (VM-only)
sidewinder exploit verify-escalation --scenario vm     # Full Rowhammer chain verification (VM-only)
```

### Full Auto
```bash
sidewinder auto --scenario host       # detect → probe → info leak
sidewinder auto --scenario vm         # detect → probe → info leak → escalation
```

## C Primitives API

All C functions are declared in `c_primitives/sidewinder.h` and exposed via ctypes in `src/sidewinder/primitives/native.py`.

### Cache Operations
- `sw_flush_line(addr)` — CLFLUSH + MFENCE on a single cache line
- `sw_flush_range(start, len)` — CLFLUSH every cache line in a range
- `sw_reload_line(addr)` — Timed load from addr, returns RDTSC delta
- `sw_cache_calibrate(addr, trials)` — Auto-calibrate hit/miss threshold
- `sw_probe_set(buffer, set_idx, stride, ways)` — Timed probe of a cache set
- `sw_prime_set(buffer, set_idx, stride, ways)` — Fill a cache set
- `sw_evict_set(buffer, set_idx, stride, ways)` — Evict a cache set via CLFLUSH

### Timing
- `sw_rdtsc()` / `sw_rdtscp()` — Read timestamp counter
- `sw_rdtsc_begin()` / `sw_rdtsc_end()` — Fenced timestamp for interval measurement
- `sw_timer_calibrate()` — Measure timer overhead
- `sw_pin_to_core(core)` — Pin process to CPU core

### Memory
- `sw_alloc_huge_pages(n)` — Reserve n huge pages (may need sudo)
- `sw_map_huge_region(size_mb)` — Allocate physically contiguous region
- `sw_virt_to_phys(vaddr)` — Virtual-to-physical address translation via /proc/self/pagemap
- `sw_get_cache_info(&info)` — CPUID cache topology (L1/L2/L3)

### Exploit Verification (Cache Side-Channel)
- `sw_spy_run_attack(output, output_size, threshold)` — Flush+Reload spy: forks victim child that reads target file, parent monitors cache to recover byte values. Uses PAGE_SIZE (4KB) stride + randomized probe order to defeat prefetchers. Returns bytes recovered.
- `sw_targeted_pte_flip(target_row, flip_bit, n_activations)` — Blacksmith-frequency hammering to flip specific PTE bit in target row. Uses non-uniform patterns to bypass TRR.
- `sw_overwrite_kernel_page(pte_addr, target_addr)` — Write arbitrary value to kernel page via flipped PTE. Requires PTE already flipped writable.
- `sw_trigger_modprobe_exec()` — Trigger kernel modprobe execution by writing to /proc/sys/kernel/modprobe_path. Creates /tmp/pwn shell script for root shell.

### TSA / Speculative Probes
- `sw_tsa_probe_sq(buf, threshold, trials, leak_count)` — TSA-SQ (Transient Scheduler Attack - Scheduler Queue): probes for leaked data via speculative load completion during false scheduler forwarding.
- `sw_ghostrace_probe(buf, threshold, trials, hit_count)` — GhostRace: detect speculative race conditions past lock primitives.
- `sw_bhi_probe(buf, threshold, trials, retrain_count)` — Branch History Injection: probe BHB poisoning from userland.
- `sw_prefetch_sidechannel_leak(buf, threshold, trials)` — AMD prefetch-based KASLR leak via prefetch timing side channel.
- `sw_kaslr_leak_kallsyms(buf)` — Leak KASLR offset via /proc/kallsyms reading (requires kptr_restrict=0).

### Rowhammer
- `sw_hammer_classic(a, b, n)` — Double-sided hammer with uniform timing
- `sw_hammer_frequency(buf, rows, n_rows, patterns, acts)` — Blacksmith frequency-based hammer
- `sw_hammer_many_sided(buf, aggressors, n, victim, acts)` — TRR-bypassing many-sided hammer
- `sw_check_flips(buf, size, &result)` — Check buffer for bit flips
- `sw_refresh_interval_measure()` — Measure DRAM refresh interval
- `sw_generate_freq_patterns(&ps, count)` — Generate Blacksmith patterns
- `sw_zenhammer_hammer(buffer, row_addrs, n_rows, patterns, acts)` — ZenHammer DDR5 hammer (AMD Zen 4 DDR5 only)

### VM-to-Host Attack Probes
- `sw_vmscape_probe(buf, threshold, trials, &leak_indicators)` — VMScape (CVE-2025-40300): BHB poisoning across VM boundaries
- `sw_l1tf_probe(buf, threshold, trials, &leak_bytes)` — L1TF/Foreshadow (CVE-2018-3615/3620/3646): L1 terminal fault guest-to-host leak
- `sw_mds_probe(buf, threshold, trials, &leaked_bytes)` — MDS/ZombieLoad (CVE-2018-12126/27/30): microarchitectural data sampling

## Adding a New CVE Profile

Add an entry to the `CVES` list in `src/sidewinder/detector/profile.py`. Each entry is a dict:
```python
{"cve": "CVE-XXXX-XXXXX", "name": "Attack Name", "class": "spectre|meltdown|mds|side_channel",
 "vendor": "Intel|AMD|ARM", "arch_filter": "!ExcludedArch|RequiredArch",
 "feature": "tsx|avx2|smt",    # optional
 "severity": "HIGH", "privilege": "unprivileged",
 "description": "..."}
```

- `arch_filter`: items prefixed with `!` are excluded architectures; items without `!` are required architectures (AND logic within each group, OR between groups).
- Use `"!"` for cross-vendor attacks with no arch filter.

## Adding a New Microarchitecture Profile

Add a tuple to `MICROARCH_PROFILES` in `src/sidewinder/detector/cpu.py`:
```python
((family, model, stepping_lo, stepping_hi), "ArchName", "Vendor", "Generation"),
```
Set both stepping values to 0 for all-stepping match.

## Modifying the Codebase
- **Python changes**: Test with `sidewinder detect` (fastest feedback) or `sidewinder probe side-channel` (tests C interop).
- **C changes**: Rebuild with `make -C c_primitives`, then test via Python.
- **CLI changes**: The CLI uses Click groups and commands. New subcommands go in the appropriate group.
- **Always run full command test** before considering a change complete:
  ```bash
  sidewinder detect && sidewinder probe side-channel && sidewinder probe speculative
  ```

## CVE/Attack Coverage Reference

Sidewinder implements detection and probing for the following CPU side-channel and Rowhammer attacks. Reference: `../docs/cpu_sidechannel_attacks_reference.md`.

### CPU Side-Channel Attacks

| Attack | CVEs | Primitive | Status |
|--------|------|-----------|--------|
| Spectre v1 (Bounds Check Bypass) | CVE-2017-5753 | Flush+Reload | detect + probe |
| Spectre v2 (BTI) | CVE-2017-5715 | Evict+Time | detect |
| Meltdown | CVE-2017-5754 | Flush+Reload | detect + probe |
| Spectre v4 (SSB) | CVE-2018-3639 | Flush+Reload | detect + probe |
| Hertzbleed | CVE-2022-23823 | DVFS timing | detect + probe |
| Foreshadow/L1TF | CVE-2018-3615/20/46 | Flush+Reload | detect |
| MDS/ZombieLoad | CVE-2018-12130, 12127, 12126 | Flush+Reload, Prime+Probe | detect |
| TAA | CVE-2019-11135 | Prime+Probe | detect |
| LVI | CVE-2020-0551 | Flush+Reload | detect |
| CacheOut | CVE-2020-0549 | Evict+Time | detect |
| SRBDS/CROSSTalk | CVE-2020-0543 | Prime+Probe | detect |
| BHI/Spectre-BHB | CVE-2022-0001/2 | Evict+Time | detect + probe |
| Retbleed | CVE-2022-29900/1 | Evict+Time | detect |
| Downfall/GDS | CVE-2022-40982 | Flush+Reload | detect + probe |
| Zenbleed | CVE-2023-20593 | Flush+Reload | detect + probe |
| Inception/SRSO | CVE-2023-20569 | Evict+Time | detect |
| GhostRace | CVE-2024-2193 | Flush+Reload | detect + probe |
| Native BHI | CVE-2024-2201 | Evict+Time | detect + probe |
| Branch Privilege Injection | CVE-2024-45332 | Evict+Time | detect |
| TSA (Transient Scheduler Attack) | CVE-2024-36350, 36357 | Flush+Reload | detect + probe |
| RFDS | CVE-2023-28746 | Flush+Reload | detect |
| AES Cache Side-Channel | (class) | Prime+Probe | probe |

### Rowhammer Attacks

| Attack | Primitive | Status |
|--------|-----------|--------|
| Classic Rowhammer (double-sided) | ACTIVATE hammering | detect + probe |
| Blacksmith (frequency-based TRR bypass) | Non-uniform patterns | probe |
| ZenHammer (DDR5 Rowhammer) | Non-uniform patterns (AMD Zen 4 DDR5) | probe |
| nbraid (many-sided) | N-sided hammering | probe |
| PTE flip escalation | Rowhammer + PTE spray | exploit (VM-only) |
| RAMBleed | Bit flip as side channel | probe |
| DRAMA (address reverse engineering) | Memory timing analysis | probe |

### Exploit Capabilities

| Capability | Attack | Scenario |
|------------|--------|----------|
| KASLR bypass | kallsyms leak, AMD prefetch side-channel | host-safe |
| Credential leak | TSA info leak, Meltdown | host-safe |
| Flush+Reload spy | spy-leak command | host-safe |
| PTE flip escalation | modprobe_path overwrite | VM-only |
| Rowhammer privilege escalation | PTE flip + write | VM-only |

### VM-to-Host Attack Probes

Sidewinder includes probes for VM-to-Host memory leakage attacks (info leak only):

| Attack | CVE | Primitive | Affected CPUs |
|--------|-----|-----------|---------------|
| VMScape | CVE-2025-40300 | Evict+Time (BHB poisoning) | AMD Zen 1-5, Intel Coffee Lake |
| L1TF/Foreshadow | CVE-2018-3615/3620/3646 | Flush+Reload (L1 terminal fault) | Intel only |
| MDS/ZombieLoad | CVE-2018-12126/27/30 | Flush+Reload (CPU buffer sampling) | Intel only |

**Note**: VM-to-host probes are read-only (info leak only). They detect BHB poisoning, L1 cache data leakage, and CPU buffer data sampling from within a VM guest.

**Usage:**
```bash
sidewinder exploit vmscape   # Probe VMScape, L1TF, and MDS from within VM
```

**Tested in QEMU VM** with AMD Family 15 Model 107 CPU. VMScape BHB poisoning detected at ~1.3MB/s leak rate.

## Manual Testing Instructions

### Prerequisites
1. Build and install sidewinder in the VM:
   ```bash
   # On host - rebuild C primitives
   make -C c_primitives

   # Copy to VM (or rebuild in VM)
   scp -P 2222 -i mordor_run/ssh/id_ed25519 \
       sidewinder/ ubuntu@localhost:/tmp/sidewinder_new/

   # In VM - reinstall
   cd /tmp/sidewinder_new
   sudo pip3 install --break-system-packages --no-build-isolation -e .
   ```

2. Set library path and verify installation:
   ```bash
   export SIDEWINDER_LIB_PATH=/tmp/sidewinder_new/c_primitives/libsidewinder.so
   sidewinder detect
   ```

### Testing VMScape (CVE-2025-40300)
VMScape works on **both AMD and Intel** CPUs. It exploits BHB poisoning across VM boundaries.

```bash
# Detect if running in a VM (should show "ubuntu" or "qemu" or similar)
cat /sys/class/dmi/id/product_name

# Run VMScape probe
sidewinder exploit vmscape

# Expected output on vulnerable system:
#   [LEAKED] VMSCAPE (CVE-2025-40300)
#            Leaked: 999 bytes/indicators
#            Rate: 1300000+ B/s
```

### Testing L1TF (Intel Only)
L1TF only affects Intel CPUs. On AMD, it will show "NOT VULN".

```bash
# Check CPU vendor
cat /proc/cpuinfo | grep "vendor_id" | head -1

# Run L1TF probe (will show NOT VULN on AMD)
sidewinder exploit vmscape

# On Intel CPU with L1TF vulnerability, expected:
#   [LEAKED] L1TF (CVE-2018-3615 / CVE-2018-3620 / CVE-2018-3646)
```

### Testing Flush+Reload Spy (Any CPU)
The spy-leak demonstrates cross-process Flush+Reload but has **limited effectiveness in virtualized environments**:

```bash
# Leak from /etc/shadow using Flush+Reload
sidewinder exploit spy-leak --target /etc/shadow

# Known limitations:
# - F+R cache timing may not work in KVM/QEMU (clflush produces no timing delta)
# - Child process cannot read /etc/shadow without root privileges
# - Falls back to /etc/hostname or /proc/self/status as readable targets
```

**Working alternative for credential leak:**
```bash
# TSA-based credential leak - reliably works on AMD Zen 3/4
sidewinder exploit credential-leak
# Output: Leaked 1024 bytes at ~20KB/s via transient scheduler attack
```

### Full Test Sequence
```bash
#!/bin/bash
export SIDEWINDER_LIB_PATH=/tmp/sidewinder_new/c_primitives/libsidewinder.so

echo "=== 1. Detection ==="
sidewinder detect

echo -e "\n=== 2. Side-Channel Probes ==="
sidewinder probe side-channel

echo -e "\n=== 3. Speculative Execution Probes ==="
sidewinder probe speculative

echo -e "\n=== 4. Hertzbleed (DVFS side-channel) ==="
sidewinder probe hertzbleed

echo -e "\n=== 5. ZenHammer (DDR5 Rowhammer) ==="
sidewinder probe zenhammer

echo -e "\n=== 6. KASLR Bypass ==="
sidewinder exploit kaslr

echo -e "\n=== 7. Credential Leak (TSA) ==="
sidewinder exploit credential-leak

echo -e "\n=== 8. VMScape (VM-to-Host, VM only) ==="
sidewinder exploit vmscape
```

### VM Environment Detection
The `_check_vm_environment()` function detects VMs by checking DMI data:
- `/sys/class/dmi/id/product_name` - e.g., "QEMU", "VMware Virtual Platform"
- `/sys/class/dmi/id/sys_vendor` - e.g., "QEMU", "VMware, Inc."
- `/sys/class/dmi/id/bios_vendor` - e.g., "SeaBIOS"

If not detected as VM, the VM-to-host probes will report "Not running in VM" but still attempt the probe.

## Verified Status (May 2026)

The following tests have been run on both host (AMD Zen 4, Family 25 Model 68) and QEMU VM (AMD Family 15 Model 107, i440FX):

### Host & VM — All Probes Working
| Probe | Result | Notes |
|-------|--------|-------|
| Side-channel calibration | ✅ excellent | F+R 99%+ hit rate, PP viable |
| TSA (CVE-2024-36350) | ✅ VULNERABLE | 200-400 leaks @ ~20KB/s |
| GhostRace (CVE-2024-2193) | ✅ VULNERABLE | 100-155 speculative hits |
| BHI (CVE-2022-0001/2201) | ✅ VULNERABLE | 500 retrains always succeed |
| SSB (CVE-2018-3639) | ✅ OK | <5 hits (noise), aligned_alloc probe |
| Spectre v1 (CVE-2017-5753) | ✅ OK | Zen 4 mitigated, native C probe |
| iTLB Multihit (CVE-2018-12207) | ✅ OK | Stable latency, no MCE |
| Hertzbleed (CVE-2022-23823) | ✅ VULNERABLE | 31-71K cycle delta |
| ZenHammer | ✅ No flips | DDR5 resistant (no TRR bypass needed) |
| VMScape (CVE-2025-40300) | ⚠️ NOT VULN (VM) | Low BHB poisoning in QEMU |
| L1TF / MDS | ✅ NOT VULN | AMD (Intel-only CVEs) |

### Exploits — What Actually Works
| Exploit | Result | Notes |
|---------|--------|-------|
| KASLR bypass | ✅ WORKS | Prefetch side-channel: kernel base recovered |
| Credential leak (TSA) | ✅ WORKS | 1024 bytes @ ~20KB/s via transient scheduler |
| Spy-leak (F+R) | ⚠️ Limited | clflush timing delta ~0 in VM; child can't read /etc/shadow |

### Key Implementation Notes
- **SSB probe**: Uses `aligned_alloc(64, 64)` for slow_ptr/val_mem to eliminate false cache conflicts from stack variable colocation.
- **Spectre v1**: Rewritten in native C (`sw_spectre_v1_probe`) — eliminates Python ctypes call overhead.
- **Hertzbleed**: `sw_hertzbleed_probe()` in `hertzbleed.c` — DVFS timing delta across power/performance data patterns.
- **ZenHammer**: `sw_zenhammer_hammer()` in `hammer.c` — Blacksmith frequency patterns on AMD Zen 4 DDR5.
- **F+R spy limitation**: In KVM/QEMU virtualized environments, clflush produces no measurable timing delta (cold≈hot≈25 cycles). The spy recovers noise, not actual file content. Use `credential-leak` (TSA) for real information leak.

## Important Conventions
- **No external binary dependencies** in the Python layer except Click, CFFI, Rich, pyelftools (all in pyproject.toml).
- **No root required** for detection and probing. Some features (huge pages, pagemap, MSR reads) need root but gracefully degrade.
- **x86_64 only** for v0.1. ARM support is a future milestone.
- **C code uses `-O3 -march=native -mtune=native`** — this is intentional for maximum hammering speed and cache timing precision.
- **Signal handling**: Be careful with SIGSEGV in ctypes code. Python's signal handler may not catch SIGSEGV from native C calls reliably. Use mitigation-status-based checks instead of actual kernel reads when possible.
- **Timed out tests are normal** for Rowhammer probing and Meltdown credential leaks. The tool reports partial results on timeout/interrupt.
