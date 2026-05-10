# Linux Kernel Exploit Primitives: Taxonomy, Page-Cache Write, and Chaining

This document covers the theoretical framework for attack primitives, the critically important page-cache write primitive family, and the methodology of chaining complementary primitives to achieve universal exploitation coverage.

For spray methods and heap exploitation techniques, see `docs/heap-exploitation.md`.
For bug class taxonomy, see `docs/bug-class-taxonomy.md`.

---

## 1. Primitive Taxonomy: Four-Type Classification

The traditional "bug-centric" approach focuses on finding vulnerabilities. The modern "capability-centric" approach focuses on the **atomic abilities** those bugs provide. This shift from "what's broken" to "what can I do" is the distinction between a vulnerability researcher and an exploit engineer.

### 1.1 The Four Primitive Types

| Type | Capability | Real-World Source | in angband |
|------|------------|-------------------|-----------|
| **Read Primitive** | Read arbitrary kernel or user memory | Info leak, UAF read, residual data | `kallsyms_leak`, msg_msg m_ts corruption |
| **Write Primitive** | Write controllable data to arbitrary kernel/user addresses | Page cache tampering, OOB write, UAF write | `modprobe_path`, `pcpu_stats`, page-cache write |
| **Execute Primitive** | Hijack kernel control flow | Corrupted function pointer, ROP chain, eBPF JIT gadget | `commit_creds` via ROP |
| **Downgrade Primitive** | Bypass security boundaries | Logic flaws, capability manipulation, reference count tricks | `userns_setup` (CAP_NET_ADMIN via namespace) |

### 1.2 Why Primitive Classification Matters

**Write primitives are the most versatile and valuable.** A reliable write primitive can often be converted to privilege escalation via:
- `modprobe_path` overwrite (write path + trigger)
- Credential corruption (write to `struct cred` fields)
- Page table modification (write to PTE entries)

**Execute primitives** (control flow hijack) are increasingly blocked by CFI, IBT, and shadow stack defenses. However, they remain viable when combined with:
- Kernel One Gadget (eBPF JIT bypass of CFI)
- Data-only attacks that corrupt function pointers

**Downgrade primitives** enable other primitives by providing necessary capabilities (e.g., CAP_NET_ADMIN for macvlan operations).

### 1.3 Primitive Capability Hierarchy

```
Level 3: Write Primitive (most versatile)
  └── modprobe_path, pcpu_stats, page-cache write
  └── Can often achieve escalation without control flow hijack

Level 2: Execute Primitive (control flow)
  └── Function pointer hijack, ROP chains
  └── Blocked by CFI/IBT, but bypasses exist

Level 1: Read Primitive (information gathering)
  └── KASLR bypass, heap address leak, credential leak
  └── Enables higher-level primitives

Level 0: Downgrade Primitive (capability gathering)
  └── Namespace creation, capability acquisition
  └── Enables other primitive paths
```

---

## 2. Page-Cache Write Primitive: The "Holy Grail"

### 2.1 What Is a Page-Cache Write Primitive?

The page cache is Linux's mechanism for caching filesystem data in memory. When a process reads a file, the kernel caches the disk blocks in memory pages. Normal writes to a file trigger Copy-On-Write (COW), allocating a new page and copying data.

A **page-cache write primitive** allows modifying these cached pages **in-place without triggering COW or writing to disk**. This means:

1. **No file permission required**: You don't need write access to the file
2. **Bypasses integrity monitoring**: IMA/EVM can't detect in-memory-only changes
3. **No disk trace**: Filesystem forensics won't see the modification
4. **High reliability**: These are deterministic logic bugs, not race conditions

### 2.2 The Dirty Family: Three Generations

| Generation | CVE | Subsystem | Write Capability | Key Innovation | Discovery |
|------------|-----|-----------|-----------------|---------------|-----------|
| **1st** | CVE-2022-0847 | Pipe | Arbitrary pipe buffer overwrite | First proof page cache tampering works | Max Kellermann |
| **2nd** | CVE-2026-31431 | AF_ALG | 4-byte direct controllable write | AI-assisted rediscovery | Theori/Xint Code |
| **3rd** | CVE-2026-43284 | xfrm-ESP + RxRPC | 4-byte + 8-byte chained | Dual-primitive universal coverage | @v4bel (Hyunwoo Kim) |

### 2.3 Dirty Pipe (CVE-2022-0847)

**Mechanism**: When a pipe buffer is spliced from a file, the `pipe_buffer.flags` `PIPE_BUF_FLAG_PACKET` flag was not checked before setting `PIPE_BUF_FLAG_WRITE`. This allowed overwriting the page cache page directly.

**Requirements**:
- No special privileges needed
- Works on all主流发行版
- No race condition required

**Limitations**: Overwrites the *same* page cache page that the victim reads from. Not a general arbitrary write.

**Reference**: https://github.com/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits

### 2.4 Copy Fail (CVE-2026-31431)

**Mechanism**: In the AF_ALG crypto subsystem, `algif_aead` uses `sock_no_splice_read()` but the data path still allows splice() to inject page cache pages into the crypto operation. The encryption/decryption then writes to these shared pages.

**Requirements**:
- No special privileges needed
- 4-byte **directly controllable** write (the auth tag output)
- Works across containers, VMs, different filesystems

**Key insight**: This was the first page-cache write primitive **rediscovered by AI** (Theori/Xint Code), proving the attack class is systematic and findable by automated tools.

**Reference**: AI-assisted discovery via Xint Code platform

### 2.5 Dirty Frag (CVE-2026-43284/CVE-2026-43500)

**Mechanism**: Two independent page-cache write primitives that each have environment limitations. When chained together, they provide universal coverage across all Linux distributions.

**Primitive 1: xfrm-ESP Write**
- **Size**: 4-byte **directly controllable** write (ESP sequence number)
- **Path**: splice() injects page cache → IPsec/ESP decryption → writes to shared page
- **Requirement**: User namespace (blocked by AppArmor `apparmor_restrict_unprivileged_userns=1` on Ubuntu)
- **Root cause introduced**: January 2017 commit "esp4/6: Avoid skb_cow_data whenever possible"

**Primitive 2: RxRPC Write**
- **Size**: 8-byte **indirectly controllable** write (fcrypt decryption output)
- **Path**: splice() injects page cache → RxRPC/Kerberos decryption → writes to shared page
- **Requirement**: **No privilege required** - fully unprivileged path
- **Control method**: Must brute-force the fcrypt key (56-bit keyspace)
- **Root cause introduced**: June 2023 RxRPC commits

**Why chaining works**:

| Environment | xfrm-ESP | RxRPC | Combined Result |
|-------------|----------|-------|-----------------|
| Ubuntu default | Blocked (AppArmor) | Works | Exploitable |
| Ubuntu + namespace allowed | Works | Works | Exploitable |
| RHEL/CentOS | Likely works | Works | Exploitable |
| Minimal containers | Blocked | Works | Exploitable |

The two primitives are **complementary**: xfrm-ESP gives precise control but needs namespaces; RxRPC works everywhere but gives indirect control. Together, they achieve **universal exploitation**.

### 2.6 Page-Cache Write Primitive Properties Summary

| Property | Value |
|----------|-------|
| **Determinism** | Logic bug, no race condition required |
| **Reliability** | Near 100% success rate |
| **Privilege required** | None (for most variants) |
| **Disk written** | No (in-memory only) |
| **IMA/EVM bypass** | Yes |
| **Cross-version stability** | High (page cache is core kernel) |
| **Discovery method** | "Primitive hunting" - enumerate all subsystems with in-place writes |
| **Mitigation** | COW enforcement, shared page marking, path isolation |

---

## 3. Primitive Chaining: From Single Bugs to Universal Exploits

### 3.1 The Chaining Paradigm

Traditional exploitation: Find ONE bug → assess exploitability → write exploit

Modern exploitation: Define capability → enumerate subsystems → chain complementary primitives

**Example - Dirty Frag**:
1. **Define target capability**: Page-cache write primitive
2. **Enumerate all subsystem paths**: xfrm-ESP (IPsec), RxRPC (AFS/Kerberos), AF_ALG (crypto)
3. **Identify environment constraints**: xfrm-ESP needs namespace, RxRPC needs fcrypt key brute-force
4. **Chain complementary primitives**: Both xfrm-ESP and RxRPC together → universal coverage

### 3.2 The "Primitive Hunting" Methodology

This is a fundamental shift in research approach:

**Old approach (Bug Hunting)**:
```
Select subsystem → Read code → Find bug → Assess exploitability
```

**New approach (Primitive Hunting)**:
```
Define desired capability → Enumerate ALL subsystem paths providing it → 
Verify deterministic logic缺陷 → Identify constraints → Chain for universal coverage
```

This approach:
- Is more systematic and complete
- Produces reusable primitives, not single-use exploits
- Enables AI-assisted scanning (enumerate all patterns systematically)
- Focuses on WHAT CAN BE DONE, not WHAT IS BROKEN

### 3.3 Chain Composition Patterns

**Pattern 1: Coverage Extension**
```
Primitive A (works in 80% of environments) + Primitive B (works in remaining 20%)
= Universal coverage
```
Example: xfrm-ESP + RxRPC

**Pattern 2: Capability Enhancement**
```
Primitive A (limited write: 4 bytes) + Primitive B (limited write: 4 bytes)
= Combined: 8-byte write
```
Example: Two OOB writes at different offsets

**Pattern 3: Escalation Bypass**
```
Bug (limited write) + SLUBStick (converts to arbitrary write)
= Full arbitrary read/write
```
Example: Limited heap bug → timing side-channel → arbitrary r/w

### 3.4 From "Bug Hunting" to "Capability Planning"

| Question | Bug Hunting | Primitive Hunting |
|----------|------------|-------------------|
| Starting point | "What bugs exist?" | "What capability do I need?" |
| Search strategy | Audit subsystem for violations | Enumerate all paths providing capability |
| Success metric | "Did I find a CVE?" | "Can I achieve universal coverage?" |
| Output | Single-use exploit | Reusable primitive chain |
| AI role | Pattern matching for bugs | Systematic enumeration of all paths |

---

## 4. Primitive Capabilities vs. Bug Classes

### 4.1 Mapping Bug Classes to Primitives

| Bug Class | Can Provide | Often Requires |
|-----------|-------------|----------------|
| UAF | Read/Write/Execute | msg_msg reclaim for data control |
| OOB Write | Write | Same-size spray or cross-cache |
| OOB Read | Read | Same-size spray for reliable reclaim |
| Double-Free | Arbitrary Free | Heap massaging |
| Race Condition | Varies (often Read/Write) | Precise timing control |

### 4.2 From Bug to Primitive Pipeline

```
Bug Discovery
    │
    ├── Classify: What type of bug?
    │       ├── UAF ──────────────────┐
    │       ├── OOB Write ─────────────┤
    │       ├── OOB Read ──────────────┤
    │       └── Double-Free ───────────┤
    │                                  ▼
    ├── Determine: What can the bug control?
    │       ├── Can write to arbitrary address?
    │       ├── Can read arbitrary memory?
    │       └── Can hijack control flow?
    │                                  │
    │                                  ▼
    └── Map to: Which primitive does this provide?
            ├── Write Primitive ──→ modprobe_path / cred corruption
            ├── Read Primitive ───→ KASLR bypass / heap leak
            ├── Execute Primitive ─→ ROP chain / function pointer
            └── Downgrade Primitive → Namespace / capability gain
```

---

## 5. Defensive Implications

### 5.1 From "CVE Fixing" to "Primitive Elimination"

Traditional defense: Find CVE → Apply patch → Problem solved

The problem: CVE is just an **instance** of a primitive. Fix one CVE, the same primitive still exists in other subsystems.

**Example**: Dirty Pipe was patched in CVE-2022-0847. But:
- Copy Fail (CVE-2026-31431) uses the same page-cache write concept in AF_ALG
- Dirty Frag (CVE-2026-43284) chains two page-cache write paths in different subsystems

**Real defense**: Eliminate the **capability** that enables the attack:
- COW enforcement on all shared page paths
- Shared page marking (SKBFL_SHARED_FRAG) to track provenance
- Architecture isolation between subsystems that process external data

### 5.2 Primitive Mitigation Matrix

| Primitive | Defense | Effectiveness |
|-----------|---------|---------------|
| Page-cache write (Dirty family) | COW enforcement | High (but breaks splice performance) |
| Page-cache write (Dirty family) | Shared page marking | Medium (path coverage) |
| msg_msg reclaim | VED msg integrity | High (but breaks legitimate use) |
| pcpu_stats corruption | Per-CPU allocation randomization | Medium |
| SLUBStick | AUTOSLAB | **Only complete mitigation** |
| commit_creds ROP | CFI/IBT | High (but JIT bypasses exist) |
| dirty_cred | VED poison-cred | High |

---

## 6. References

### Page-Cache Write Primitive

| Resource | URL |
|----------|-----|
| Dirty Pipe original write-up | https://dirtypipe.cm4all.com/ |
| Copy Fail (Theori) | AI-assisted discovery via Xint Code |
| Dirty Frag (@v4bel) | https://v4bel.github.io/ |
| xfrm-ESP root cause commit | git commit esp4/6: Avoid skb_cow_data (Jan 2017) |

### Primitive Taxonomy & Exploitation Theory

| Resource | Relevance |
|----------|-----------|
| This document is the canonical reference for primitive taxonomy in angband |
| See `docs/heap-exploitation.md` for spray methods |
| See `docs/bug-class-taxonomy.md` for bug class mapping |
| See `docs/vkb.md` for external reference index |

---

## 7. Quick Reference: angband Primitive Registry

See `angband/primitives/registry.py` for implementation.

| Primitive | Type | Status |
|-----------|------|--------|
| `msg_msg_spray` | Groom | Implemented |
| `pipe_buffer_spray` | Groom | Implemented |
| `setxattr_spray` | Groom | Implemented |
| `dirty_cred_spray` | Groom | Implemented |
| `modprobe_path` | Write | Implemented |
| `dirty_pagetable` | Write | Implemented |
| `commit_creds` | Execute | Implemented |
| `netlink_ops` | Downgrade | Implemented |
| `userns_setup` | Downgrade | Implemented |
| `pcpu_stats` | Write | Implemented |
| `kallsyms_leak` | Read | Implemented |
| `page_cache_write` | Write | **TODO: Not yet implemented** |

**Note**: `page_cache_write` primitive for the Dirty family is documented here but not yet implemented in the framework. This represents a gap in current coverage.