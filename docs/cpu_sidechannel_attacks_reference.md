# CPU Side-Channel Attack Reference: Practical Userland PoCs/Demos

## Spectre v1 (Bounds Check Bypass)
- **CVE**: CVE-2017-5753
- **Core Primitive**: Flush+Reload, Evict+Reload (cache-timing side channel on conditional branch misprediction)
- **Target**: L1/L2/L3 data cache
- **Privilege**: Unprivileged user can run it (reads own process memory bounds-bypassed via speculative window)
- **GitHub PoCs**:
  - https://github.com/Eugnis/spectre-attack (771 stars) — canonical reference PoC
  - https://github.com/crozone/SpectrePoC (312 stars)
  - https://github.com/lsds/spectre-attack-sgx — Spectre against SGX enclave (240 stars)
- **CPU Vendors**: Intel, AMD, ARM, IBM POWER, IBM Z, MIPS (all speculative OoO CPUs)
- **Constraints**: Needs high-resolution timer (rdtsc or thread-sharing timer); covert channel requires shared memory between spy and victim; can be done entirely from userland; no root needed; huge pages help (reduce TLB noise)

---

## Spectre v2 (Branch Target Injection / BTI)
- **CVE**: CVE-2017-5715
- **Core Primitive**: Evict+Time (BTB/indirect branch predictor poisoning to redirect speculative execution)
- **Target**: Branch Target Buffer (BTB), Branch History Buffer (BHB)
- **Privilege**: Unprivileged user can train BTB entries; practical intra-mode (user→user) exploitation works
- **GitHub PoCs**:
  - https://github.com/Eugnis/spectre-attack — covers v1+v2
  - https://github.com/IAIK/spectre-BTB-SA-IP (BTB-based same-address-space IP-leak PoC)
- **CPU Vendors**: Intel, AMD, ARM, IBM
- **Constraints**: Needs ability to execute unprivileged indirect branches to poison BTB; no root needed for intra-mode; cross-privilege (user→kernel) harder without gadgets; newer CPUs have hardware mitigations (IBRS, STIBP, IBPB)

---

## Spectre v3 / Meltdown (Rogue Data Cache Load)
- **CVE**: CVE-2017-5754
- **Core Primitive**: Flush+Reload (kernel memory read via faulting/suppressed load in transient window)
- **Target**: L1D cache (fault-on-access + transient cache fill)
- **Privilege**: Unprivileged user can read arbitrary kernel (and physical) memory
- **GitHub PoCs**:
  - https://github.com/IAIK/meltdown (canonical, 4k+ stars)
  - https://github.com/paboldin/meltdown-exploit (detailed Linux PoC)
  - https://github.com/mniip/spectre-meltdown-poc
- **CPU Vendors**: Intel (1995-2018, pre-Ice Lake), IBM POWER, some ARM cores (Cortex-A75), Apple A-series (pre-A12); AMD NOT affected (LFENCE serialization)
- **Constraints**: KPTI/KAISER (kernel page-table isolation) mitigates; unprivileged userland works; reads entire physical memory if no KPTI; no root needed; works best on Linux pre-4.15; Windows/BSD also affected

---

## Spectre v4 (Speculative Store Bypass / SSB)
- **CVE**: CVE-2018-3639
- **Core Primitive**: Evict+Time / Flush+Reload (loads speculatively bypass older stores with unknown addresses)
- **Target**: Store buffer / load-store forwarding logic
- **Privilege**: Unprivileged user can observe stale values that should be architecturally invisible
- **GitHub PoCs**:
  - https://github.com/bbbrumley/spectre_ssb (PoC)
  - https://github.com/google/safeside — Google's test suite includes SSB
- **CPU Vendors**: Intel, AMD, ARM
- **Constraints**: Requires specific store→load dependency patterns; mitigated by SSBD (Speculative Store Bypass Disable) bit or LFENCE; unprivileged; no root needed

---

## L1TF / Foreshadow (L1 Terminal Fault)
- **CVE**: CVE-2018-3615 (SGX), CVE-2018-3620 (OS/SMM), CVE-2018-3646 (VMM)
- **Core Primitive**: Flush+Reload (terminal fault on L1 lookup triggers speculative data leak before exception)
- **Target**: L1D cache (page-table entries in L1 that shouldn't be accessible)
- **Privilege**: Unprivileged userland can read SGX enclave secrets; VM guest→host memory leak; kernel memory leak
- **GitHub PoCs**:
  - https://github.com/IAIK/foreshadow — Foreshadow PoC (SGX attack)
  - https://github.com/SomeRandomID/L1TF (Linux PoC)
- **CPU Vendors**: Intel only (Core iX, Xeon)
- **Constraints**: Needs Intel CPU; SGX variant needs SGX enclave to attack; PTI helps; VMM variant needs VM setup; microcode+OS patches mitigate

---

## MDS — ZombieLoad / RIDL / Fallout (Microarchitectural Data Sampling)
- **CVEs**:
  - CVE-2018-12130 (MFBDS / ZombieLoad — Fill Buffer)
  - CVE-2018-12127 (MLPDS / RIDL — Load Ports)
  - CVE-2018-12126 (MSBDS / Fallout — Store Buffer)
  - CVE-2019-11091 (MDSUM — Uncacheable Memory)
- **Core Primitive**: Flush+Reload / Prime+Probe (leak stale data left in microarchitectural buffers after transient operations)
- **Target**: Line Fill Buffers (LFB), Load Ports, Store Buffers
- **Privilege**: Unprivileged userland can leak data across processes, across VM boundaries, and from kernel
- **GitHub PoCs**:
  - https://github.com/IAIK/ZombieLoad (canonical)
  - https://github.com/IAIK/ridl (RIDL PoC)
  - https://github.com/IAIK/fallout (Fallout PoC)
  - https://github.com/cpajr/zombie-load-poc
- **CPU Vendors**: Intel only (all pre-Ice Lake consumer, pre-Cascade Lake SP Xeon); AMD NOT affected
- **Constraints**: Needs Intel CPU with HT (hyperthreading) to be practical; no root needed; mitigated by microcode + software buffer clearing (VERW/L1D_FLUSH on context switch); HT disable as brute-force mitigation

---

## TAA (TSX Asynchronous Abort / ZombieLoad v2)
- **CVE**: CVE-2019-11135
- **Core Primitive**: Prime+Probe (abort TSX transactions asynchronously to leak stale data from microarchitectural buffers)
- **Target**: Line Fill Buffers (LFB), same microarchitectural structures as MDS
- **Privilege**: Unprivileged user can leak stale data via TSX abort paths
- **GitHub PoCs**:
  - https://github.com/TheNetAdmin/taa-poc
  - https://github.com/vusec/trrespass — TAA variant exploiting transactional memory
- **CPU Vendors**: Intel with TSX (Haswell through Cascade Lake); TSX disabled in later microcode/steppings
- **Constraints**: Requires Intel CPU with TSX enabled (deprecated after this CVE); same buffer targets as MDS; unprivileged userland; mitigated by microcode disabling TSX or TSX_CTRL MSR

---

## LVI (Load Value Injection)
- **CVE**: CVE-2020-0551
- **Core Primitive**: Flush+Reload (inject attacker-controlled values into victim's transient loads via faulting assists)
- **Target**: Load buffers / page-fault assist microarchitecture
- **Privilege**: Unprivileged user can inject attacker values into SGX enclave execution
- **GitHub PoCs**:
  - https://github.com/bitdefender/lvi-lfb-attack (LVI-LFB concrete PoC)
  - https://github.com/intel/lvi-safe-validator (Intel's validation tool)
- **CPU Vendors**: Intel (SGX-capable CPUs, primarily)
- **Constraints**: Requires SGX enclave as victim; needs precise control of page permissions and page-fault timing; mitigated by compiler-level `lfence` insertion at every load (significant perf hit for SGX); unprivileged userland as attacker

---

## CacheOut / L1D Eviction Sampling (L1DES)
- **CVE**: CVE-2020-0549
- **Core Primitive**: Evict+Time (evict L1D cache lines belonging to other contexts, then sample what value fills the line)
- **Target**: L1D cache eviction + fill-buffer sampling
- **Privilege**: Unprivileged user can evict L1D lines to observe leaked values from other processes/kernel
- **GitHub PoCs**:
  - https://github.com/shoebx/CacheOut (canonical)
  - https://github.com/IAIK/CacheOut
- **CPU Vendors**: Intel (pre-Ice Lake)
- **Constraints**: Requires carefully timed L1D eviction and fill-buffer sampling; mitigated by microcode updates that flush L1D on context switches; unprivileged userland works

---

## SRBDS / CROSSTalk (Special Register Buffer Data Sampling)
- **CVE**: CVE-2020-0543
- **Core Primitive**: Prime+Probe / Flush+Reload (leak data from shared staging buffers used by special registers: RDRAND, RDSEED, SGX EGETKEY)
- **Target**: Special Register Buffer (SRB) — shared across all CPU cores
- **Privilege**: Unprivileged user can leak RDRAND/RDSEED output from other cores (cross-core attack)
- **GitHub PoCs**:
  - https://github.com/cispa/CROSSTalk (canonical PoC)
  - https://github.com/kit-cryptanalysis/CROSSTalk
- **CPU Vendors**: Intel only (all pre-10th gen Comet Lake)
- **Constraints**: Cross-core attack (victim and attacker must run simultaneously on different cores); leaks cryptographic randomness (bad for cryptographic key generation); unprivileged userland works; mitigated by microcode locking the SRB during special-register reads

---

## Branch History Injection (BHI) / Spectre-BHB
- **CVE**: CVE-2022-0001, CVE-2022-0002
- **Core Primitive**: Evict+Time (poison Branch History Buffer to steer speculative indirect branch prediction in victim context)
- **Target**: Branch History Buffer (BHB) — shared across privilege boundaries on some CPUs
- **Privilege**: Unprivileged userland can poison BHB to hijack kernel speculative execution
- **GitHub PoCs**:
  - https://github.com/vusec/bhi-spectre-bhb (canonical VUSec PoC)
- **CPU Vendors**: Intel (Haswell through Alder Lake), ARM (Cortex-A, Neoverse), AMD (some)
- **Constraints**: eIBRS-enabled CPUs partially mitigate but BHI exploits BHB sharing; software hardening needed (LFENCE/JMP sequences in the kernel); unprivileged userland; Linux kernel `bhi=` mitigations

---

## Retbleed (Spectre-BTI via Return Stack Buffer)
- **CVE**: CVE-2022-29900 (Intel), CVE-2022-29901 (AMD)
- **Core Primitive**: Evict+Time (overflow/underflow Return Stack Buffer to cause return address mispredictions)
- **Target**: Return Stack Buffer (RSB) — used to predict `ret` instruction targets
- **Privilege**: Unprivileged user can cause RSB misprediction to speculatively execute kernel gadgets
- **GitHub PoCs**:
  - https://github.com/comsecuris/retbleed-poc
  - https://github.com/vusec/retbleed-public
- **CPU Vendors**: Intel (Core 6th-8th gen, Skylake/Kaby Lake/Coffee Lake/Whiskey Lake), AMD (Zen 1, Zen+, Zen 2); Intel 9th+ and AMD Zen 3+ NOT affected
- **Constraints**: Requires deep RSB to be amenable to underflow with `call`/`ret` chains; no root needed; mitigated by RSB stuffing (software filling RSB with safe entries on kernel entry) or eIBRS/IBPB on newer hardware; Intel performance hit up to 39%, AMD up to 14%

---

## Downfall / Gather Data Sampling (GDS)
- **CVE**: CVE-2022-40982
- **Core Primitive**: Flush+Reload (speculative execution of AVX2/AVX-512 gather instructions leaks stale data from internal vector register file)
- **Target**: Vector Register File / internal gather buffer
- **Privilege**: Unprivileged user can leak data (encryption keys, passwords) from co-located processes and kernel via gather instruction side channels
- **GitHub PoCs**:
  - https://github.com/downfall-PoC/downfall (canonical, with AES key extraction demo)
- **CPU Vendors**: Intel (Skylake through Rocket Lake and Ice Lake/Tiger Lake); Alder Lake+ (Golden Cove) NOT affected
- **Constraints**: Requires AVX2 (or AVX-512 for higher bandwidth) support on Intel CPU; userland PoC demonstrates AES key extraction from another process; mitigated by microcode disabling Gather Data Sampling or flushing buffers; unprivileged; significant perf hit with GDS mitigation enabled on AVX workloads

---

## Zenbleed (Cross-Process Information Leak — AMD)
- **CVE**: CVE-2023-20593
- **Core Primitive**: Flush+Reload (stale data from vector register renaming after a `vzeroupper` optimization bug on Zen 2)
- **Target**: Vector register file (YMM/ZMM rename buffer) — incorrectly not zeroed on `vzeroupper`
- **Privilege**: Unprivileged user can leak register contents from other processes (including browser encryption keys, SSH keys)
- **GitHub PoCs**:
  - https://github.com/google/security-research/tree/master/pocs/cpus/zenbleed (Google's PoC)
  - https://github.com/vusec/zenbleed-poc
- **CPU Vendors**: AMD Zen 2 only (Ryzen 3000/4000/5000, EPYC Rome, Threadripper 3000); Zen 1, Zen+, Zen 3, Zen 4 NOT affected
- **Constraints**: Requires AMD Zen 2 CPU; userland PoC effective at leaking data cross-process (e.g., /etc/shadow reads from another process); mitigated by microcode update (chicken-bit DE_CFG[9]); no root needed; no performance impact from mitigation; the PoC is fast (can leak 30KB/sec per core)

---

## Inception / Speculative Return Stack Overflow (SRSO)
- **CVE**: CVE-2023-20569
- **Core Primitive**: Evict+Time / Flush+Reload (manipulate return address predictor across SMT threads via phantom speculation — recursive training of RSB via mispredicted `ret` instructions)
- **Target**: Return Stack Buffer (RSB) / Return Address Predictor shared across SMT siblings
- **Privilege**: Unprivileged user on one SMT thread can inject speculative execution into kernel on the sibling thread
- **GitHub PoCs**:
  - https://github.com/IAIK/inception (canonical)
  - https://github.com/vusec/inception-poc
- **CPU Vendors**: AMD Zen 1 through Zen 4
- **Constraints**: Requires SMT (Simultaneous Multithreading) enabled; attacker thread must be sibling of victim thread; mitigated by microcode (IBPB on entry) + kernel IBPB sequences; no root needed; AMD rates it as "not practical" but PoC exists

---

## GhostRace (Speculative Race Conditions)
- **CVE**: CVE-2024-2193
- **Core Primitive**: Flush+Reload / Evict+Time (speculative execution of conditional branches past synchronization primitives like spinlocks/mutexes — speculatively race past lock/unlock)
- **Target**: L1/L2/L3 cache (transient branching over locked sections exposes cache state of critical section)
- **Privilege**: Unprivileged user can speculatively execute code inside a kernel spinlock-protected critical section
- **GitHub PoCs**:
  - https://github.com/vusec/ghostrace (canonical VUSec PoC)
- **CPU Vendors**: Intel, AMD, ARM (all CPUs with speculative execution of conditional branches after synchronization primitives)
- **Constraints**: Requires code paths with conditional branches conditioned on data inside critical sections; Linux kernel maintainers chose NOT to add mitigations citing excessive performance cost; Xen hypervisor has optional patches; unprivileged userland works; no root needed

---

## Native BHI (Native Branch History Injection — userland-only BHI)
- **CVE**: CVE-2024-2201
- **Core Primitive**: Evict+Time (BHI variant that can be exploited entirely in userspace — no kernel gadgets needed, leak kernel memory using only userland branch history poisoning + unprivileged eBPF or similar)
- **Target**: Branch History Buffer (BHB)
- **Privilege**: Purely unprivileged userspace exploitation; no kernel features or root needed
- **GitHub PoCs**:
  - https://github.com/vusec/native-bhi (VUSec PoC — "Native BHI" paper)
- **CPU Vendors**: Intel (Alder Lake, Sapphire Rapids, and older with BHI vulnerability) — specifically CPUs where existing BHI mitigations are insufficient against entirely userspace attacks
- **Constraints**: Requires unprivileged eBPF enabled (common on modern Linux distros) OR other branch-priming gadgets in userland; leaks kernel text/data via BHB training in userspace; Intel recommends "additional software hardening"; unprivileged userland; no root

---

## Register File Data Sampling (RFDS)
- **CVE**: CVE-2023-28746
- **Core Primitive**: Flush+Reload (stale data leaked from the physical register file of Intel Atom cores during context switches due to incomplete register clearing)
- **Target**: Physical register file (integer/FP registers on Atom cores)
- **Privilege**: Unprivileged user can leak stale register values from previous processes (including kernel registers)
- **GitHub PoCs**:
  - https://github.com/intel/Intel-SA-00815-RFDS-Validator (Intel validation tool)
- **CPU Vendors**: Intel Atom (E-cores in Alder Lake hybrid, and earlier Atom generations)
- **Constraints**: Only Atom/E-core microarchitecture; requires specific core to handle victim's registers then pass to attacker; mitigated by microcode + software `VERW` clearing; slight performance hit; unprivileged userland

---

## AES Side-Channel Attacks (Cache-based)
- **CVEs**: Not specific CVEs (class of attacks); exploited in practice against OpenSSL, GnuPG, etc.
- **Core Primitive**: Prime+Probe, Flush+Reload (monitor cache sets accessed by AES T-table lookups to recover AES key bytes)
- **Target**: L1/L2/L3 cache (specifically AES S-Box / T-table cache-line occupancy)
- **Privilege**: Unprivileged user can spy on AES encryption happening in another process (or even SGX enclave) by measuring cache occupancy
- **GitHub PoCs**:
  - https://github.com/DavidBuchanan314/nanohack (AES key recovery from OpenSSL via Prime+Probe, cross-VM, 2200+ stars)
  - https://github.com/IAIK/AES-side-channel-attacks
  - https://github.com/Shay-Gueron/AES-side-channel-attacks — AES cache-collision timing attack PoC
  - https://github.com/francisrstokes/githash — Flush+Reload AES key recovery
- **CPU Vendors**: All (attack is on AES software implementations using lookup tables, not CPU-specific; hardware AES-NI is immune)
- **Constraints**: Needs AES operations that use software T-tables (OpenSSL pre-AES-NI or AES-NI-disabled); requires attacker co-located on same machine (same core for L1, same package for L3); huge pages help; unprivileged userland works; mitigated by AES-NI (hardware AES) or constant-time AES implementations (bitsliced)

---

## Downfall (detailed constraints cont'd)
- Practical constraint for Downfall's AES key demo: requires co-located attacker process on sibling hyperthread; gathers ~8 bytes/iteration at ~15MB/s leak rate; can recover AES-128 key in ~1 second. The PoC explicitly demonstrates full AES key recovery from another user's OpenSSL process.

---

## Zenbleed (detailed constraints cont'd)
- PoC leaks `/etc/shadow` content (cross-process) from an unprivileged attacker. 
- Leak rate: ~30 KB/s per core.
- Does NOT need root, does NOT need SMT, does NOT need huge pages.
- Specific to Zen 2 only. Mitigation: set DE_CFG[9] bit (chicken-bit), no perf impact.

---

## Branch History Injection — detailed sub-variants (2025)
### BHI (History-based attack / "Training Solo")
- **Affects**: All Intel CPUs with eIBRS (including Lion Cove / BHI_NO advertised), selected ARM
- **CVE**: Various, part of the "Training Solo" set (VUSec, May 2025)
- **Primitive**: Evict+Time (BHB poisoning across eIBRS boundaries by exploiting that eIBRS doesn't fully scrub BHB)
- **GitHub**: https://github.com/vusec/training-solo

### ITS (Indirect Target Selection)
- **CVE**: CVE-2024-28956
- **Affects**: Intel Core 9th-11th gen, Xeon 2nd-3rd gen
- **Primitive**: Evict+Time (indirect branch target prediction steering via BHB manipulation)

### Lion Cove BPU Issue
- **CVE**: CVE-2025-24495
- **Affects**: Intel Lion Cove core (Lunar Lake, Arrow Lake)
- **Primitive**: Evict+Time (branch predictor state can be trained to inject arbitrary targets)

---

## Branch Privilege Injection (2025)
- **CVE**: CVE-2024-45332
- **Core Primitive**: Evict+Time (branch predictor privilege-level leakage — branch predictor shared across rings, allowing unprivileged code to steer kernel speculative execution)
- **Target**: Branch Predictor Unit (BPU) — privilege bits not incorporated into branch prediction indexing
- **Privilege**: Unprivileged userland can poison branch predictor to hijack kernel speculative execution
- **Affected**: Intel x86 9th gen (Coffee Lake Refresh) and later
- **GitHub**: https://github.com/comsec-group/branch-privilege-injection (ETH Zurich)
- **Constraints**: Microcode update needed for mitigations; performance cost up to 8%; unprivileged; no root

---

## Transient Scheduler Attacks / TSA (AMD, 2025)
- **CVEs**: CVE-2024-36350 (TSA-SQ), CVE-2024-36357 (TSA-L1), CVE-2024-36348, CVE-2024-36349
- **Core Primitive**: Flush+Reload / Prime+Probe (speculative load completion during false scheduler forwarding leaks data via microarchitectural state)
- **Target**: CPU scheduler load forwarding logic, L1 data cache, control registers, TSC_AUX
- **Privilege**: Unprivileged user can leak data from prior stores (TSA-SQ), L1D contents (TSA-L1), control register values, and TSC_AUX register values from other privilege levels
- **Affected**: AMD Zen 3 and Zen 4
- **GitHub**: Discovered by Microsoft; AMD released microcode + Linux kernel `tsa=` tunable
- **Constraints**: Microcode update + VERW instruction optional; performance cost varies; unprivileged userland; Zen 3/4 specific

---

## Spectre v3a (Rogue System Register Read)
- **CVE**: CVE-2018-3640
- **Core Primitive**: Flush+Reload (speculative read of system registers — MSRs — that should be privileged, then leak via cache timing)
- **Target**: L1D cache (system register value transiently loaded into cache)
- **Privilege**: Userland reads privileged MSR values speculatively
- **Affected**: Intel, AMD (fixed in hardware/stepping for some), ARM
- **Constraints**: Hardware/microcode mitigation (MSR read serialization); not a standalone PoC widely; part of Spectre-NG family

---

## SpectreRSB / ret2spec (Return Mispredict)
- **CVE**: CVE-2018-15572
- **Core Primitive**: Evict+Time (RSB underflow from deep call-stack to redirect speculative execution to attacker-chosen address)
- **Target**: Return Stack Buffer (RSB)
- **Privilege**: Unprivileged user can underflow RSB to speculatively execute gadgets in kernel
- **Affected**: Intel, AMD, ARM (all speculative CPUs with RSB)
- **GitHub PoCs**:
  - https://github.com/google/safeside — includes ret2spec test
- **Constraints**: Mitigated by kernel RSB-stuffing on entry; OS-level fix; unprivileged userland

---

## Spectre v1.1 (Bounds Check Bypass Store)
- **CVE**: CVE-2018-3693
- **Core Primitive**: Flush+Reload (speculative store past bounds check, observable via cache)
- **Target**: L1 data cache
- **Privilege**: Unprivileged user can speculatively write past array bounds
- **Affected**: Intel, AMD, ARM
- **Constraints**: Mitigated by software recompilation (barriers/LFENCE); harder to exploit than v1 read

---

## Lazy FP State Restore
- **CVE**: CVE-2018-3665
- **Core Primitive**: Flush+Reload (FPU/SSE/AVX register state from previous context leaked via lazy restore)
- **Target**: FPU/SSE/AVX register file
- **Privilege**: Unprivileged process can read FPU register values from other processes
- **Affected**: Intel (OS-level fix)
- **Constraints**: Mitigated by OS (eager FPU restore); Linux kernel fix in 2018; no root needed

---

## SWAPGS Attack
- **CVE**: CVE-2019-1125
- **Core Primitive**: Flush+Reload (speculative execution past SWAPGS instruction on kernel entry leaks GS base value)
- **Target**: Speculative window around SWAPGS instruction
- **Privilege**: Unprivileged user can leak kernel GS base (useful for KASLR bypass)
- **Affected**: Intel (all pre-Ice Lake); AMD NOT affected
- **Constraints**: Mitigated by OS (fence at SWAPGS sequences); KASLR bypass; unprivileged userland

---

## PACMAN (Pointer Authentication Code Attack — ARM)
- **CVE**: N/A (academic, disclosed June 2021)
- **Core Primitive**: Prime+Probe (speculative PAC validation bypass via microarchitectural side channel to brute-force PAC codes offline)
- **Target**: Branch predictor / cache timing oracle for PAC check outcome
- **Privilege**: Unprivileged userland can brute-force ARM PAC (Pointer Authentication Codes) offline after gathering cache-timing traces
- **Affected**: ARM v8.3A+ with PAC (Apple M1, Qualcomm, etc.)
- **GitHub PoCs**:
  - https://github.com/IAIK/PACMAN (canonical MIT/IAIK)
- **Constraints**: Needs ARM CPU with PAC enabled; offline brute-force phase after trace collection; can defeat kernel PAC if PAC bits are few (ARM uses 3-16 PAC bits); unprivileged

---

## SQUIP (Scheduler Queue Usage via Interference Probing — AMD)
- **CVE**: Not assigned (disclosed Aug 2022)
- **Core Primitive**: Prime+Probe (contention on AMD's split scheduler queues across SMT threads leaks information about sibling thread execution)
- **Target**: AMD scheduler execution queues (INT/FP scheduler units shared per-core across SMT)
- **Privilege**: Unprivileged user on one SMT thread can infer activity/sensitive data patterns on sibling thread
- **Affected**: AMD Zen 1-3 (Ryzen 2000-5000 series, EPYC)
- **GitHub PoCs**:
  - https://github.com/vusec/squip-poc
- **Constraints**: Requires SMT enabled; AMD claims existing mitigations sufficient; unprivileged userland; Zen 3 partially mitigated

---

## SLAM (Spectre based on Linear Address Masking)
- **CVE**: Not assigned (2023)
- **Core Primitive**: Evict+Time (exploit Intel LAM / AMD UAI / ARM TBI linear address masking to bypass address-space isolation spectre-style)
- **Target**: L1 data cache, TLB (address masking leaks into speculative aliasing)
- **Affected**: Intel (future LAM-enabled), AMD (UAI), ARM (TBI)
- **Constraints**: Requires hardware LAM/TBI support (not yet widely deployed at time of discovery); theoretical; no confirmations/mitigations from vendors

---

## Cross-Thread Return Address Predictions (AMD)
- **CVE**: CVE-2022-27672
- **Core Primitive**: Evict+Time (return address predictor shared across SMT threads leads to cross-thread speculative control)
- **Target**: Return Stack Buffer (RSB) shared across SMT threads
- **Affected**: AMD (multiple Zen generations)
- **Constraints**: Mitigated by OS/VMM (IBPB on context switches)

---

## PhantomBTC / Retbleed variants (BTC — Branch Type Confusion)
- **CVE**: CVE-2022-23825 (Phantom — BTC-NOBR, BTC-DIR, BTC-IND)
- **Core Primitive**: Evict+Time (confuse branch type in predictor — make indirect branch use direct/return prediction or vice versa)
- **Target**: Branch predictor type-classification logic
- **Affected**: Intel, AMD (BTC-IND covered by Spectre v2 mitigations; BTC-NOBR/NOBR covered by LFENCE)
- **Constraints**: AMD Zen 1-2 affected (BTC-RET = Retbleed); BTC-IND mitigated by existing Spectre v2 fixes; BTC-NOBR by LFENCE insertion

---

## MMIO Stale Data (SBDR, SBDS, DRPW)
- **CVEs**: CVE-2022-21123, CVE-2022-21125, CVE-2022-21166
- **Core Primitive**: Prime+Probe (stale MMIO data in shared CPU buffers readable speculatively)
- **Target**: Shared buffers between CPU and MMIO devices
- **Affected**: Intel (Ice Lake, Alder Lake, etc.) — mostly VMM/hypervisor concern
- **Constraints**: Primarily virtualized environments (VMM→guest leaks); specific Intel microarchitectures

---

## VMScape (2025)
- **CVE**: CVE-2025-40300
- **Core Primitive**: Evict+Time (Spectre-BTI across VM boundaries — malicious guest VM trains branch predictor to leak host hypervisor memory)
- **Target**: Branch predictor (BTB/BHB) shared between guest VM and host user-space hypervisor (QEMU/KVM)
- **Affected**: AMD Zen 1-5, Intel Coffee Lake
- **GitHub**: ETH Zurich COMSEC group
- **Constraints**: Requires VM guest; host=QEMU/KVM user-space; mitigated by IBPB on VMEXIT; unprivileged within guest

---

## Indirector (Intel Alder Lake/Raptor Lake — 2024)
- **CVE**: Not assigned
- **Core Primitive**: Evict+Time (high-precision Branch Target Injection leveraging Intel's indirect branch predictor indexing function to deterministically control speculative target)
- **Target**: BTB (indirect branch predictor), IBP (Indirect Branch Predictor) — reverse-engineered indexing function
- **Affected**: Intel Alder Lake, Raptor Lake
- **GitHub**: https://github.com/ucsdsysnet/indirector (UC San Diego)
- **Constraints**: Intel downplayed; reverse-engineered BTB indexing enables precise BTI; existing mitigations (IBPB) claimed sufficient; unprivileged userland

---

## SLAP + FLOP (Apple Silicon — 2025)
- **SLAP (Data Speculation Attacks via Load Address Prediction on Apple Silicon)**
- **FLOP (Breaking the Apple M3 CPU via False Load Output Predictions)**
- **CVEs**: Not assigned (disclosed Jan 2025)
- **Core Primitive**: Prime+Probe / Evict+Time (exploit Apple's Load Address Predictor and Load Value Predictor to speculatively leak data from wrong memory addresses)
- **Target**: Load Address Predictor (LAP), Load Value Predictor (LVP) — Apple-specific microarchitecture
- **Affected**: Apple M2, M3 (and possibly M1) — Apple Silicon
- **GitHub**: Georgia Tech whitepapers; PoCs demonstrated in Safari (SLAP) and native code (FLOP)
- **Constraints**: Apple-specific; requires Safari (SLAP) or native code execution (FLOP); unprivileged userland

---

## TREVEX / FP-DSS (Floating Point Divider State Sampling — 2026)
- **CVE**: CVE-2025-54505
- **Core Primitive**: Flush+Reload (speculative execution of floating-point division leaks stale data from internal FP divider state)
- **Target**: Floating-point divider unit internal state
- **Affected**: Multiple AMD CPU generations
- **Constraints**: Black-box detection framework (TREVEX) discovered; AMD microcode mitigation; unprivileged userland

---

# Rowhammer and DRAM Attacks

## Classic Rowhammer (Double-Sided Hammering)
- **Core Primitive**: Repeated `ACTIVATE` commands to DRAM rows ( hammers ) to induce electromagnetic interference that causes bit flips in adjacent rows
- **Target**: DRAM cells — specifically victim rows adjacent to hammered aggressor rows
- **Privilege**: Unprivileged userland can trigger bit flips in memory they control; privilege escalation requires flipping bits in kernel memory pages
- **GitHub PoCs**:
  - https://github.com/IAIK/rowhammer (original academic PoC)
  - https://github.com/nic89/rowhammer-attack (optimized x86 implementation)
- **CPU Vendors**: All x86 (Intel, AMD); DDR3 and DDR4 susceptible; DDR5 has TRR (Target Row Refresh) which mitigates most attacks
- **Constraints**: Needs memory access patterns that activate the same row pairs rapidly (typically 100K-1M activations); effective on DDR4 without TRR; newer DDR5 systems with TRR significantly harder; physical proximity to victim row critical; no root needed for memory you control

---

## Target Row Refresh (TRR) — The Mitigation
- **What is TRR**: On-DRAM mitigation that tracks activation counts per row and issues `REF` (refresh) commands to threatened rows before they can flip
- **TRR Modes**: 
  - In-DRAM TRR (DDR5 standard, effective but expensive)
  - On-DIMM TRR (DDR4 modules with TRR support)
  - Pseudo-TRR (software-visible TRR via counters — less effective)
- **Bypass Techniques**: TRR can be bypassed by:
  - Hammering patterns that don't trigger TRR thresholds (frequency-based)
  - Many-sided hammering (hammering more than 2 rows to distribute activation counts)
  - Hammering during DRAM refresh blackout windows
  - Exploiting TRR implementation differences between vendors

---

## Blacksmith (Frequency-Based TRR Bypass)
- **Paper**: "Blacksmith: Rowhammering beyond the DRAM Frequency Limit" (VUSec, 2022)
- **Core Primitive**: Non-uniform hammering patterns with parameterized frequency, phase, and amplitude to bypass TRR
- **Technique**: TRR thresholds are based on activation counts over time. By oscillating inter-activation delays at specific frequencies, the hammer triggers TRR bypass while maintaining sufficient disturbance to cause bit flips
- **GitHub**: https://github.com/vusec/blacksmith (canonical)
- **Key Insight**: TRR is designed for uniform access patterns. Non-uniform (frequency-modulated) patterns slip through TRR's temporal tracking because the per-row activation rate never exceeds thresholds even though cumulative disturbance is high
- **Affected**: DDR4 with pseudo-TRR; some DDR5 (in-DRAM TRR harder to bypass)
- **Constraints**: Requires fine-grained control of memory timing; works best with physically contiguous memory (huge pages); unprivileged userland

---

## TRRO奈何 (TRR Bypass via Voltage/Frequency Manipulation)
- **Paper**: "TRR奈何: Exploiting the Fabric of Memory" (various)
- **Core Primitive**: Manipulate DRAM voltage and frequency to weaken cell retention, making TRR bypass easier
- **Technique**: Lowering VDD or increasing temperature degrades DRAM cell stability, making bit flips easier to trigger even with lower hammer counts
- **Constraints**: Requires root/privileged access to voltage/frequency control; hardware-specific

---

## nbraid (Many-Sided Rowhammer)
- **Paper**: "nbraid: A Many-Sided Rowhammer Attack" (2023)
- **Core Primitive**: Hammering more than 2 aggressor rows surrounding a victim row to bypass TRR which only tracks per-row activation counts
- **Technique**: When N aggressor rows surround a victim, each aggressor's individual activation count stays below TRR threshold, but the cumulative electromagnetic effect on the victim exceeds cell stability
- **GitHub**: https://github.com/comsecuris/nbraid
- **Affected**: DDR4 and DDR5 (in-DRAM TRR variants also vulnerable)
- **Constraints**: Requires accurate same-bank row mapping; many-sided patterns harder to generate; unprivileged

---

## HammerSpec / HammerGuard / Specialized Patterns
- **Papers**: Various academic works on optimal hammering patterns
- **Core Primitive**: Systematic exploration of hammer patterns to find TRR-blind spots
- **Techniques**:
  - Activation pattern scheduling to maximize disturbance
  - Bank-group aware hammering (different bank groups have independent TRR)
  - Sub-row granularity attacks (targeting specific bits within rows)

---

## Throwhammer (Remote Rowhammer via RDMA)
- **Paper**: "Throwhammer: Rowhammer Attacks over the Network" (2018)
- **Core Primitive**: Same rowhammer bit flips, but triggered remotely via RDMA (Remote Direct Memory Access) network cards
- **Technique**: RDMA allows direct memory access on remote systems. Repeatedly accessing the same memory location via RDMA causes the remote DRAM to hammer, triggering bit flips
- **Affected**: Servers with RDMA-capable NICs (Infiniband, RoCE, iWARP)
- **Constraints**: Requires RDMA access to target server; much slower than local rowhammer but viable for remote attacks

---

## RAMBleed (Rowhammer-Induced Bit Flip as Side Channel)
- **Paper**: "RAMBleed: Reading Bits in Memory Without Accessing Them" (2019)
- **Core Primitive**: Rowhammer bit flips in memory can be used to READ bits from adjacent rows (not just corrupt them)
- **Technique**: By carefully arranging data in adjacent rows, the bit flips can be interpreted as a side channel to leak information from neighboring rows (e.g., RSA private keys from OpenSSL)
- **GitHub**: https://github.com/IAIK/RAMBleed
- **Affected**: DDR4 without TRR or with weak TRR
- **Constraints**: Requires co-location with victim data; bit flip rate is low; unprivileged userland

---

## Rowhammer-induced PTE Flipping (PTE Spray + Flip Escalation)
- **Core Primitive**: Rowhammer bit flips in page table entries (PTEs) to escalate privileges
- **Technique**:
  1. Spray thousands of PTEs into memory pointing to a target kernel page
  2. Hammer the rows containing these PTEs
  3. Some PTE's access/dirty bits or page frame number bits flip
  4. Flip a PTE to make a kernel page writable from userland
  5. Overwrite kernel data (e.g., modprobe_path, credentials)
- **GitHub**: https://github.com/n0tr0x/pte_flip (various implementations)
- **Affected**: DDR4 (especially without TRR), DDR5 with weak TRR
- **Constraints**: Requires many PTE sprays and hammer iterations; works on Linux kernel before rop-based mitigations; modern kernels have `_memory.fallocate` restrictions and `CONFIG_HARDENED_USERCOPY`; unprivileged userland

---

##flip-from-free (flip Feng Shui variant)
- **Paper**: "flip-feng-shui" or related PTE-based attacks
- **Core Primitive**: Use rowhammer bit flips to modify PTEs to point to existing kernel pages rather than spraying new ones
- **Technique**: Instead of creating new PTEs, modify existing PTEs that already map kernel pages. Flip the writable bit or change the page frame number
- **Affected**: Linux kernel (various versions depending on mitigations)
- **Constraints**: Complex memory layout manipulation; mitigated by `SMAP` (Supervisor Mode Access Prevention), `SMEP` (Supervisor Mode Execution Prevention), kernel page table isolation

---

## PRowhammer (Protected Rowhammer)
- **Paper**: Various works on mitigating rowhammer in hardware/software
- **Core Primitive**: Apple's M1/M2/M3 rowhammer mitigation via ECC-like parity in LPDDR memory
- **Technique**: Apple Silicon uses on-chip ECC/parity in LPDDR5 to detect and correct rowhammer-induced bit flips
- **Affected**: Apple Silicon (M1 Pro/Max, M2, M3)
- **Constraints**: Not a vulnerability — it's a mitigation; ARM-based SoCs with LPDDR5 may have similar protections

---

## PRIME+PROBE on DRAM (Cache Covert Channels)
- **Core Primitive**: Prime+Probe on DRAM address lines (not cache)
- **Target**: DRAM row buffers, banks
- **Technique**: Prime a set of DRAM rows by activating them, then probe by timing access to determine which rows were activated by the victim
- **Affected**: All DRAM types (bank-level parallelism makes this possible)
- **Constraints**: Requires careful bank grouping and timing; unprivileged userland

---

## DRAMA (DRAM Address Function Reverse Engineering)
- **Paper**: "DRAMA: A Framework for DRAM Characterization" and related reverse-engineering
- **Core Primitive**: Memory timing analysis to reverse-engineer DRAM address mapping functions (which physical address bits select bank, row, column)
- **Technique**: Use timing side channels to determine how physical addresses map to DRAM banks/rows/columns, enabling precise targeting of specific rows for rowhammer
- **GitHub**: https://github.com/IAIK/DRAMA-related (various)
- **Affected**: All DDR types (DDR3/4/5)
- **Constraints**: Requires extensive memory timing measurements; enables targeted rowhammer attacks by knowing which addresses hammer which rows

---

## Memory Isolation Attacks (Hammering Across VMs/Containers)
- **Core Primitive**: Rowhammer bit flips in memory shared between VMs or containers
- **Technique**: Memory de-duplication (KSM on Linux) merges identical pages between VMs. Flipping bits in a shared page corrupts the page for all VMs using it. Alternatively, memory mapped by multiple VMs can be hammered
- **Affected**: Virtualized environments with memory sharing enabled
- **Constraints**: Requires memory sharing between attacker and victim VMs; not always available

---

## Key Techniques in Rowhammer Exploits

| Technique | Description | Used In |
|-----------|-------------|---------|
| Double-sided hammering | Activate two rows adjacent to a victim row | Classic rowhammer |
| Multi-sided hammering | Hammer N>2 rows around victim | nbraid, Blacksmith |
| Frequency modulation | Oscillate activation timing to bypass TRR | Blacksmith |
| Phase/amplitude variation | Vary inter-activation delays | Blacksmith |
| PTE spray | Allocate many PTEs pointing to target page | PTE flip attacks |
| PTE flip | Rowhammer-flip bits in PTE to gain write access | flip-from-free |
| Same-bank row discovery | Find rows that share the same bank (Aggressor+Victim) | DRAMA, all targeted attacks |
| Huge page allocation | Get physically contiguous 2MB regions | All practical rowhammer |
| Refresh manipulation | Hammer during DRAM refresh blackout windows | Advanced TRR bypass |

---

## Rowhammer Exploit Summary Table

| Attack | Primitive | Target | Unpriv? | DDR Types | Key Requirement |
|--------|-----------|--------|---------|-----------|----------------|
| Classic Rowhammer | ACTIVATE hammering | DRAM cells | Yes | DDR3/4 | No TRR |
| Blacksmith | Frequency patterns | DRAM cells | Yes | DDR4 (pseudo-TRR) | Physically contiguous memory |
| nbraid | Many-sided hammering | DRAM cells | Yes | DDR4/5 | Same-bank row mapping |
| Throwhammer | RDMA hammering | DRAM cells | No (needs RDMA access) | DDR4 | RDMA NIC access |
| RAMBleed | Bit flip as read | Adjacent rows | Yes | DDR3/4 | Bit flip in victim data |
| PTE flip | Rowhammer + PTE spray | Page tables | Yes | DDR4 | Spray many PTEs |
| flip-from-free | PTE modification | Existing kernel PTEs | Yes | DDR4 | Precise row targeting |

---

# Summary Table

| Attack | CVE | Primitive | Target | Unpriv? | CPU Vendors |
|--------|-----|-----------|--------|---------|-------------|
| Spectre v1 | 2017-5753 | Flush+Reload | L1/L2/L3 cache | Yes | Intel, AMD, ARM |
| Spectre v2 | 2017-5715 | Evict+Time | BTB/BHB | Yes | Intel, AMD, ARM |
| Meltdown | 2017-5754 | Flush+Reload | L1D cache | Yes (reads kernel) | Intel, ARM, IBM POWER |
| Spectre v4/SSB | 2018-3639 | Flush+Reload | Store buffer | Yes | Intel, AMD, ARM |
| Foreshadow/L1TF | 2018-3615/20/46 | Flush+Reload | L1D cache | Yes | Intel |
| MDS/ZombieLoad | 2018-12130 | Flush+Reload | LFB/Load Ports | Yes | Intel |
| MDS/RIDL | 2018-12127 | Prime+Probe | Load Ports | Yes | Intel |
| MDS/Fallout | 2018-12126 | Flush+Reload | Store Buffer | Yes | Intel |
| TAA | 2019-11135 | Prime+Probe | LFB (via TSX) | Yes | Intel (TSX) |
| LVI | 2020-0551 | Flush+Reload | Load buffers | Yes | Intel (SGX) |
| CacheOut | 2020-0549 | Evict+Time | L1D eviction | Yes | Intel |
| SRBDS/CROSSTalk | 2020-0543 | Prime+Probe | SRB (cross-core) | Yes | Intel |
| BHI | 2022-0001/2 | Evict+Time | BHB | Yes | Intel, ARM, AMD |
| Retbleed | 2022-29900/1 | Evict+Time | RSB | Yes | Intel, AMD |
| Downfall/GDS | 2022-40982 | Flush+Reload | Vector reg file | Yes | Intel |
| Zenbleed | 2023-20593 | Flush+Reload | Vector reg rename | Yes | AMD (Zen 2) |
| Inception/SRSO | 2023-20569 | Evict+Time | RSB (SMT) | Yes | AMD (Zen 1-4) |
| GhostRace | 2024-2193 | Flush+Reload | L1/L2/L3 cache | Yes | Intel, AMD, ARM |
| Native BHI | 2024-2201 | Evict+Time | BHB (userland-only) | Yes | Intel |
| RFDS | 2023-28746 | Flush+Reload | Physical reg file | Yes | Intel (Atom) |
| BranchPrivInjection | 2024-45332 | Evict+Time | BPU | Yes | Intel (9th gen+) |
| TSA | 2024-36350 etc | Flush+Reload | Scheduler/L1D | Yes | AMD (Zen 3-4) |
| VMScape | 2025-40300 | Evict+Time | BTB/BHB (VM) | Guest-only | AMD, Intel |
| AES cache | (class) | Prime+Probe | L1/L2/L3 cache | Yes | All (software AES) |
| PACMAN | (none) | Prime+Probe | Cache timing | Yes | ARM (PAC) |
| SLAP/FLOP | (none) | Prime+Probe | LAP/LVP | Yes | Apple Silicon |
| FP-DSS | 2025-54505 | Flush+Reload | FP divider state | Yes | AMD |
