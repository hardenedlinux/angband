# Kernel Defense-in-Depth: Exploit Mitigation Taxonomy

A catalog of kernel self-protection technologies (KSPP, grsecurity, VED, LKRG) that detect or prevent exploitation. Used by Angband to understand why certain CVEs fail and which mitigations they defeat.

## Defense Categories

| Category | Mechanism | Example |
|----------|-----------|---------|
| Shadow data | Maintain separate copy of critical data; verify on use | LKRG cred check, VED msg protecting |
| Hash tracking | Hash critical objects; verify hash before use | kern_integ, core_pattern protection |
| Slab poisoning | Set/checks poison values on slab allocation/free | VED poison-cred, kmem_cache poison |
| Code-based checks | Verify operation parameters against known-safe patterns | VED msg length matching, pipe_buffer ops |
| Memory isolation | Separate memory regions by type/sensitivity | AUTOSLAB, SLAB_VIRTUAL, userfaultfd |

## VED — Vault Exploit Defense (HardenedVault)

VED is a grsecurity-inspired exploit prevention system that intercepts kernel allocators and critical operations to detect exploitation patterns.

### VED Mitigation Matrix

| Mitigation | Blocks | CVE Examples | Doesn't Block |
|-----------|--------|-------------|---------------|
| VED msg protecting | msg_msg reconnaissance, OOB read via msg_msg | CVE-2021-22555 (with msg) | pipe, setxattr sprays |
| VED pipe-buffer protecting | pipe_buffer page-UAF | CVE-2022-0847 (via pipe) | msg_msg, setxattr |
| VED poison-cred | arbitrary free of struct cred | CVE-2021-26708 (cred-jar spray) | Single-free cred corruption |
| VED core_pattern | core_pattern overwrite | All modprobe_path exploits | signalfd cred overwrite |
| VED slab poisoning | abnormal cross-cache reuse patterns | SLUBStick (partial) | Deterministic cross-cache |
| CPU pinning disabled | Heap shaping for spray determinism | ~20-30% reduction in spray success | Doesn't block exploitation |

### Source

See `docs/vkb.md` → VED — Vault Exploit Defense for full source reference.

### Key Insight

VED blocks most data-only attacks by detecting the **spray/reclaim step** rather than the write primitive step. The most resilient exploits avoid VED's protected object types entirely:

- **DirtyPipe** (CVE-2022-0847): Not blocked by VED — pipe buffer overflow bypasses both msg protecting and pipe-buffer protecting because it corrupts pipe_buffer internal state, not the buffer itself
- **CVE-2021-22555**: Exploitable with 3 different technique variants; VED blocks msg-based approach but not others

## LKRG — Linux Kernel Runtime Guard

**Source**: See `docs/vkb.md` → LKRG for full source reference.

LKRG provides runtime integrity checking across multiple kernel subsystems:

### LKRG Protection Mechanisms

```
1. Credential checking:
   - Tracks struct cred allocations in kmem_cache
   - Detects cred object corruption (uid, gid, caps)
   - Hooks: cred_alloc_blank, cred_prepare, commit_creds

2. Process checking:
   - Monitors task_struct for unexpected modifications
   - Detects ptrace attaching to privileged processes

3. Interrupt descriptor table (IDT) checking:
   - Verifies IDT entries haven't been modified
   - Detects vector-injection attacks

4. SIndiana int3 / AC'97:
   - Detects code modifications via self-modifying code patterns
```

### LKRG Limitations

- Performance overhead (~3-5%) prevents it from being mainstream
- Detects but does not prevent all exploitation patterns
- Can be bypassed by corrupting LKRG's own data structures (LKRG-kill exploits exist)
- Does not protect against information leaks (KASLR bypass still works)

## AUTOSLAB — Slab Object Isolation

**Source**: PaX/GRsecurity (2024+)

AUTOSLAB is the only mitigation that **completely kills SLUBStick** and most cross-cache attacks by isolating each `kmalloc` type into a dedicated slab cache:

```
Without AUTOSLAB (all kmalloc-256 share one cache):
  timerfd_ctx (kmalloc-256) ← freed
  io_kiocb (kmalloc-256)    ← freed
  net_device (kmalloc-256) ← freed
  → All reuse same slab pages → cross-cache possible

With AUTOSLAB (each kmalloc-256 gets dedicated cache):
  timerfd_ctx_cache: only timerfd_ctx objects
  io_kiocb_cache: only io_kiocb objects
  net_device_cache: only net_device objects
  → timerfd_ctx freed → only timerfd_ctx reallocated there
  → Cross-cache requires buddy-level page reuse (much harder)
```

### Why AUTOSLAB Works

1. **Removes cross-cache attack surface**: Each object type lives in isolation
2. **Makes cross-size spraying impossible**: kmalloc-256 for timerfd_ctx cannot reclaim kmalloc-512 for net_device
3. **Kills SLUBStick's cross-cache path**: SLUBStick relies on buddy reusing a freed slab page for a different cache; AUTOSLAB prevents different cache types from sharing pages
4. **Minimal performance cost**: Modern allocators already have per-CPU caches; AUTOSLAB extends this to per-type isolation

### Status

AUTOSLAB is in active development (as of 2026). Mainline kernel integration is pending upstream review.

## CONFIG_RANDOM_KMALLOC_CACHES

Since kernel 6.2, this option randomizes the mapping between kmalloc caches and slab pages:

```
Without: kmalloc-256 → slab_page_A (deterministic)
With:    kmalloc-256 → random_cache → slab_page_Z (probabilistic)
```

### Effectiveness Against Exploits

| Exploit Type | Effectiveness |
|--------------|---------------|
| Blind cross-cache | Moderate (probabilistic obstruction) |
| SLUBStick | Partial (SLUBStick adapts by spraying across all caches) |
| Deterministic single-spray | None (if attacker knows target cache) |

### Bypass

Spray through **all kmalloc caches simultaneously** (512+ allocations). Costly but deterministic.

## CONFIG_SLAB_VIRTUAL

Remaps slab pages into a separate virtual address range, breaking physmap-based attacks that rely on physical-to-virtual address correlation:

```
Without: phys_addr = virt_to_phys(obj) → predictable
With:    phys_addr = random_from_pool → physmap correlation broken
```

### Bypass

- **Cross-cache attacks** still work (don't depend on physmap)
- **SLUBStick** still works (uses buddy allocator, not physmap)
- CVE-2025-38617 physmap bypass (technique #12) is blocked

## CONFIG_SLAB_FREELIST_HARDENED

XOR's the freelist pointer with a per-slab random value and the slab's address:

```
Freelist pointer stored: actual_addr XOR random XOR slab_addr
```

### Effectiveness

| Attack | Blocked? |
|--------|----------|
| Arbitrary free chaining | Yes |
| UAF read (no free chain) | No |
| Direct write primitive | No |
| SLUBStick | No |

This mitigation blocks **freelist manipulation attacks** (paradigm 2 code-reuse via corrupted function pointers stored in freed objects) but does not block data-only attacks (paradigm 3).

## TYPED_KMALLOC_CACHES (Clang 22)

**Source**: Marco Elver patch series (2026)

Compiler-assisted type-based cache partitioning via Clang 22 "allocation tokens":

```cpp
// Without: all pipe_buffer go to generic kmalloc caches
// With:    each allocation type gets typed cache

pipe_buffer *p = alloc(sizeof(*p), GFP_KERNEL, TOKEN(pipe_buffer));
// → pipe_buffer_cache (dedicated, type-enforced)
```

### Difference from AUTOSLAB

| Aspect | RANDOM_KMALLOC_CACHES | TYPED_KMALLOC_CACHES |
|--------|----------------------|---------------------|
| Isolation basis | Random per-callsite | Deterministic by type |
| Requires compiler support | No | Yes (Clang 22+) |
| Breaks type confusion | No | **Yes** |
| Breaks cross-cache | No | **Yes** |

## Defense Selection for Kernel Hardening

| Goal | Recommended Mitigation Stack |
|------|------------------------------|
| Block data-only attacks (modprobe_path, signalfd) | VED core_pattern + VED poison-cred |
| Block heap spray/reclaim | VED msg protecting + VED pipe-buffer protecting + AUTOSLAB |
| Block CFI bypass (ROP/JOP) | FineIBT + CFI + shadow stack |
| Block SLUBStick | **AUTOSLAB** (only full mitigation) |
| Block info leaks | KASLR + kernel stack canary + randomize_page |
| Block arbitrary code injection | NX + SMEP + SMAP + PAN |

## References

All sources consolidated in `docs/vkb.md`.
