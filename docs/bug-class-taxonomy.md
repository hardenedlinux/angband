# Bug Class Taxonomy & Modern Exploitation Techniques

Based on PaX attack paradigms, modern kernel exploitation research, and the angband exploit framework.

## PaX Attack Paradigms (pax-future.txt, 2003)

The foundational classification of exploitation from the PaX team:

| Level | Attack Type | Description | Defense |
|-------|------------|-------------|---------|
| (1) | Arbitrary code execution | Inject + execute new code | NOEXEC, MPROTECT |
| (2) | Existing code out of order | ROP/JOP/COP - reuse existing code | CFI, shadow stack |
| (3) | Existing code in order, arbitrary data | Data-only attacks - corrupt data structures | DFI, AUTOSLAB |

**Key insight**: Level (3) is "probably equivalent to the halting problem" - there is no generic solution. Data-only attacks are the most stealthy and hardest to detect.

## Bug Classes & Angband Mapping

### Use-After-Free (UAF)

| CVE | Subsystem | Object | Exploitation Technique | Status |
|-----|-----------|--------|----------------------|--------|
| CVE-2026-23209 | macvlan | net_device | pcpu_stats -> increment (too weak for modprobe_path) | NAMESPACE ROOT ONLY |

### Exploitation Approaches for UAF

```
UAF Bug
  │
  ├── Function pointer hijack (Level 2 attack)
  │   ├── msg_msg reclaim → controlled func ptr
  │   │   ├── wake_up_locked_poll → entry->func()
  │   │   ├── hrtimer.function → callback
  │   │   ├── perf_event.destroy → function pointer
  │   │   └── io_task_work.func → task work callback
  │   │
  │   └── Commit_creds escalation (one-shot)
  │       └── ROP: push rdi;pop rsp → xor edi,edi → commit_creds(0) → root
  │
  ├── Data-only corruption (Level 3 attack)
  │   ├── Corrupt cred struct → uid=0
  │   ├── Corrupt modprobe_path → write + trigger
  │   ├── Corrupt core_pattern → crash → payload exec
  │   └── Page-level UAF → cross-cache corruption
  │
  └── Arbitrary free chain
      ├── msg_msg.mlist.next → kfree(other object)
      ├── msg_msg.security → kfree
      └── Double-free → heap massaging → arbitrary object reclaim
```

## msg_msg: The Universal Heap Spray Primitive

The `msg_msg` structure is the **most versatile heap spray primitive** in Linux kernel exploitation. It forms the backbone of angband's exploitation strategy.

### Structure Layout
```c
struct msg_msg {            /* 48 bytes header */
    struct list_head m_list; /* 0-15 */
    long m_type;             /* 16-23 */
    size_t m_ts;             /* 24-31 */
    struct msg_msgseg *next; /* 32-39 */
    void *security;          /* 40-47 */
    /* mtext follows at offset 48 */
};
```

### Exploitation Capabilities

| Capability | Mechanism | Used By |
|-----------|-----------|---------|
| **Heap spray** | Controllable size (48 to PAGE_SIZE) → any slab cache | All angband CVEs |
| **Arbitrary read** | Corrupt `m_ts` → out-of-bounds read via msgrcv() | CVE-2021-26708, CVE-2021-22555 |
| **Arbitrary free** | Corrupt `mlist.next` → kfree other objects | CVE-2021-22555 |
| **Arbitrary free (2)** | Corrupt `security` → kfree target | CVE-2021-26708 |
| **Object reclaim** | Free target → spray msg_msg → controlled data at freed address | All UAF exploits |
| **Function pointer control** | msg_msg occupies freed object → mtext overlays function pointers | timerfd, perf, io_uring |

### msg_msg Offset Mapping (Verified: pahole 6.8.0-106)

For a freed object reclaimed by msg_msg, the mapping is:

```
Freed object byte 0    → msg_msg.m_list (0-15) [NOT controllable]
Freed object byte 16   → msg_msg.m_type (16-23) [NOT controllable]
Freed object byte 24   → msg_msg.m_ts (24-31) [NOT controllable]
Freed object byte 32   → msg_msg.next (32-39) [NOT controllable]
Freed object byte 40   → msg_msg.security (40-47) [NOT controllable]
Freed object byte 48   → msg_msg.mtext[0] ← START OF CONTROLLABLE AREA
Freed object byte 48+N → msg_msg.mtext[N]
```

**Critical**: Function pointers at offsets < 48 within the freed object CANNOT be controlled via mtext. For timerfd_ctx, `hrtimer.function` at offset 40 falls in the msg_msg header (security field), making direct hijack impossible via msg_msg spray alone.

## SLUB Allocator Internals

### Slab Cache Architecture

```
kmalloc-256 slab:
  Page 0: [obj_0][obj_1]...[obj_N][free_list]
  Page 1: [obj_0][obj_1]...[obj_N][free_list]
  ...

kmalloc-256-cg slab:  (accounted, different page)
kmalloc-256-rcl slab: (reclaimable, different page)
```

### Key Mitigations

| Mitigation | Kernel Version | Effect on Exploitation |
|-----------|---------------|----------------------|
| Separate accounted caches (kmalloc-cg) | v5.14 | msg_msg (accounted) goes to -cg, other objects go elsewhere |
| CONFIG_RANDOM_KMALLOC_CACHES | v6.6 | Multiple randomized caches per size → reduced spray success |
| Per-call-site caches (code tagging) | v6.11 | Each allocation site gets its own cache → AUTOSLAB-like isolation |
| PaX AUTOSLAB | PaX only | Complete per-type isolation → kills cross-cache attacks |
| Hardware MTE (ARM v8.5+) | Hardware | Memory tagging catches UAF at hardware level |

### SLUBStick: Cross-Cache Attack (2024)

**Mechanism**: Timing side-channel on SLUB allocator → convert limited heap bug to arbitrary r/w.

**Requirements**:
- CPU pinning (reliability ~90% with pinning, ~70% without)
- Precise slab cache knowledge
- Controlled allocation/deallocation timing

**Mitigation**:
- AUTOSLAB: **Only known complete solution** (kills the bug class)
- RANDOM_KMALLOC_CACHES: Reduces reliability but doesn't prevent
- CPU pinning restriction: Reduces success rate
- MAC (SELinux/AppArmor): Prevents binary execution in /tmp

## Heap Spray Techniques

### angband-Implemented Methods

| Method | Target Cache | Notes |
|--------|-------------|-------|
| **msg_msg spray** | 48 to PAGE_SIZE bytes | Primary method, used in all CVEs |
| **pipe_buffer spray** | kmalloc-64 to kmalloc-1k | pipe_buffer=40B (kmalloc-64), pipe_inode_info larger |
| **slab drain** | kmalloc-4k | macvlan exploit pattern fill |

### Other Known Methods

| Method | Reference | Notes |
|--------|-----------|-------|
| **cred-jar spray** (DirtyCred) | CVE-2021-26708 | Arbitrary free → cred cache spray → uid=0 |
| **Page-level UAF** | Phrack #71 | Cross-cache → buddy allocator → arbitrary page reclaim |
| **setxattr spray** | Various | Needs userfaultfd, fills arbitrary slab caches |
| **keyctl spray** | Various | Uses keyring allocations |
| **signalfd spray** | Various | Alternative to timerfd for kmalloc targets |

## Escalation Paths in angband

### Path A: modprobe_path (Write-Based)
```
[UAF] → [write primitive] → overwrite modprobe_path → trigger modprobe → root
```
- Modprobe_path address: `0xffffffff90dde440` (6.8.0-106)
- Need: arbitrary write to kernel memory
- Used by: CVE-2026-23209 (via pcpu_stats corruption)

### Path B: commit_creds (Code Execution)
```
[UAF] → [func ptr hijack] → ROP chain → commit_creds(0) → root
```
- commit_creds: `0xffffffff8e7472f0` (6.8.0-106)
- prepare_kernel_cred: `0xffffffff8e747870`
- Need: stack pivot gadget + ROP chain

### Path C: dirty_pagetable (Page-Level)
```
[UAF] → [page drain] → PTE reclaim → arbitrary write → modprobe_path
```
- Used by: CVE-2026-23209 full exploit
- Breaks CONFIG_RANDOM_KMALLOC_CACHES isolation

### Path D: dirty_cred (Cred Corruption)
```
[UAF] → [arbitrary free] → cred_jar spray → uid=0
```
- Stealthiest (no control flow violation)
- Detected by VED poison-cred and LKRG cred integrity

## Foundational Escalation Techniques

### ret2usr (Return to User)

The most basic privilege escalation technique: corrupt a function pointer or return address to redirect execution to user-space code, then use `commit_creds(prepare_kernel_cred(0))` or similar.

```
Requirements: Function pointer hijack, SMEP disabled/bypassed
Mitigation: SMEP (blocks user memory access from kernel mode)
```

### ret2dir (Return to Directory)

Exploits the fact that certain kernel memory regions (kernel text, rodata, data) are simultaneously mapped into both kernel and user virtual address spaces.

```
Requirements: KASLR base leak, arbitrary write
Mitigation: kernel text relocation (not default)
```

### ret2page (Dedicated Cache)

Similar to ret2dir but uses the "dedicated cache" concept - exploiting allocations that map the same physical pages at both kernel and user addresses.

```
Requirements: Page-level UAF, KASLR bypass
Source: CVE-2022-32226 (nfc/driver)
```

### PTMA (Page Table Manipulation Attack)

Manipulates page table entries directly to bypass hardware protections (SMEP, SMAP, NX).

```
1. Get a known physical page (e.g., via UAF)
2. Modify PTE to redirect at arbitrary kernel address
3. Write via userspace address → writes to kernel address
```
Source: 2020 - "PTMA: Attacking the core of memory permission"

## Modern Defense Taxonomy

### VED (Vault Exploit Defense) Mitigations (2026 Update)

| Feature | Type | Targets | Effectiveness |
|---------|------|---------|---------------|
| msg_msg integrity check | Hash-based | m_ts, next, security corruption | High |
| Out-of-bound read check | Boundary check | Infoleak via msgrcv() | High |
| poison-cred | Slab poison | cred_jar heap spray | High |
| pipe-buffer protect | Code logic check | Pipe page UAF | Medium |
| core pattern hash | Hash tracking | modprobe_path/core_pattern overwrite | Medium |
| CPU pinning restriction | Attack surface | Heap shaping success rate | ~20-30% reduction |
| RO guard | Shadow data | Sensitive data corruption | Medium |

**VED 2026 Analysis** (Sep 2025): Data-only attacks dominate post-CFI era. CFI cannot detect credential corruption, pipe_buffer page UAF, or modprobe_path overwrite. VED transitions from CFI-focused to DFI (Data Flow Integrity) approach.

### LKRG (Linux Kernel Runtime Guard)

- Cred integrity: Shadow copy of credentials, detects unauthorized modification
- kern_integ: Hash-based integrity checks on kernel text/data
- Post-exploitation detection: Limited post-escalation process existence

### PaX/GRsecurity

| Feature | Attack Class Prevented |
|---------|----------------------|
| NOEXEC | (1) Code injection |
| MPROTECT | (1) W+X mapping |
| ASLR | (1)(2)(3) Probabilistic |
| CFI | (2) ROP/JOP |
| AUTOSLAB | (3) Cross-cache heap attacks |
| KERNSEAL | (3) Kernel data integrity |
| RAP | (2) Return address protection |

### Attack → Defense Mapping

```
Level (1): Code Injection
  └── Defense: NOEXEC, MPROTECT, KERNEXEC

Level (2): Control Flow Hijack (ROP/JOP/COP)
  ├── Defense: CFI, shadow stack, RAP
  ├── Bypass: COF (Coroutine-Oriented Programming) - BH USA 2025
  └── Bypass: Data-only → avoid CFI checks entirely

Level (3): Data-Only Attacks
  ├── cred corruption → VED poison-cred, LKRG cred integrity
  ├── modprobe_path → VED core pattern hash
  ├── msg_msg abuse → VED msg integrity + OOB check
  ├── pipe page UAF → VED pipe-buffer protect
  ├── SLUBStick cross-cache → AUTOSLAB (only complete defense)
  └── CPU pinning → Attack surface reduction
```

## Spray Selection Guide for angband

Given a UAF on object of size N in cache kmalloc-S:

| Scenario | Recommended Spray | Why |
|----------|------------------|-----|
| N < 48 | Hard - msg_msg header > object | Use keyctl/setxattr instead |
| 48 ≤ N ≤ 256 | msg_msg spray | Most common, direct control via mtext |
| 256 < N ≤ 1024 | msg_msg + msg_msgseg | Multi-segment spray |
| N > 1024 | pipe_buffer or slab drain | Large objects |
| Cross-cache needed | dirty_pagetable (page-level) | Breaks slab isolation |
| Need cred corruption | dirty_cred (cred-jar spray) | Direct cred overwrite |

## References

- PaX Future: https://pax.grsecurity.net/docs/pax-future.txt
- VED 2026 DFI Security: https://hardenedvault.net/blog/2025-09-17-dfi-security/
- msg_msg Recon & VED: https://hardenedvault.net/blog/2022-11-13-msg_msg-recon-mitigation-ved/
- SLUBStick Risk Assessment: https://hardenedvault.net/blog/2024-08-25-slubstick-risk-assessment-embedded-system/
- AUTOSLAB: https://grsecurity.net/how_autoslab_changes_the_memory_unsafety_game
- DirtyPipe: https://github.com/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits
- pipe_primitive: https://github.com/veritas501/pipe-primitive
- Page UAF (Phrack #71): https://phrack.org/issues/71/13
- SLUBStick paper: https://stefangast.eu/papers/slubstick.pdf
- RANDOM_KMALLOC_CACHES: https://sam4k.com/exploring-linux-random-kmalloc-caches
- pipe_buffer AARW: https://a13xp0p0v.github.io/2026/04/20/pipe-buffer-experiments.html
- Linear Mapping KASLR Bypass: https://googleprojectzero.blogspot.com/2025/11/defeating-kaslr-by-doing-nothing-at-all.html
- MSG_OOB UAF: https://googleprojectzero.blogspot.com/2025/08/from-chrome-renderer-code-exec-to-kernel.html
- CVE-2024-50264 Analysis: https://a13xp0p0v.github.io/2025/09/02/kernel-hack-drill-and-CVE-2024-50264.html
