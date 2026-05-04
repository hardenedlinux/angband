# Novel Kernel Exploitation Techniques

A catalog of cutting-edge exploitation techniques extracted from Google kernelCTF winning submissions and the broader security research community. These techniques go beyond the standard UAF-reclaim-function-pointer-hijack pattern and represent the state of the art in kernel exploit development.

## 1. LL_ATK — Linked List Attack

**Source**: CVE-2025-38477 (QFQ race condition), $82k payout  
**Authors**: Google kernelCTF submission

### Technique

LL_ATK converts a UAF via kernel linked-list unlink operations into code execution **without requiring a heap address leak**. This is revolutionary — traditionally, crafting fake list entries required knowing the kernel heap address.

```
Normal UAF exploitation (requires heap leak):
  Freed object → msg_msg reclaim → fake struct → func ptr hijack
                                           ↑
                                    Needs kernel heap address
                                    for linked list pointers

LL_ATK (NO heap leak needed):
  Freed object → unlink from list → type confusion →
    fake node insertion → kernel traverses our node → code execution
```

### Mechanism

1. A freed kernel object is on a doubly-linked list (`list_head` or `hlist_node`)
2. The list's `__list_del()` operation writes `prev->next = next` and `next->prev = prev`
3. Through a type confusion bug, one of these pointers lands on a field that, when interpreted as a different type, becomes a function pointer
4. The kernel calls the corrupted function pointer
5. **Key insight**: the kernel's own list operations provide the write — we don't need to know addresses

### Relevance to Angband

The timerfd UAF (CVE-2026-35555) has `timerfd_ctx` on the `cancel_list`. However, the current kernel correctly calls `timerfd_remove_cancel()` → `list_del_rcu()` → `hrtimer_cancel()` → `kfree_rcu()` in sequence, removing the ctx from the list before freeing it. LL_ATK would require a scenario where the list unlink happens *after* the object is freed — or where a type confusion makes the `list_del` write target a function pointer field. Currently the timerfd code path does not provide this; the `list_del_rcu` happens before `kfree_rcu`, closing the window. LL_ATK exploitation for timerfd requires either a different kernel version with reordered cleanup or a separate vulnerability that can corrupt the cancel_list structure.

---

## 2. NPerm — Kernel Image Area Payload Placement

**Source**: CVE-2025-38477 (QFQ race), $82k payout  
**Authors**: @n132 and @kyle

### Technique

NPerm exploits a kernel design issue where pages used during early boot are released back to the buddy allocator but remain **mapped** at their original kernel image addresses. This allows attackers to place payloads at predictable kernel addresses without needing a heap address leak.

```
Normal exploitation:
  UAF → need heap leak → place ROP chain at known heap address

NPerm exploitation:
  UAF → mmap pages → kernel image areas still mapped → place ROP chain at known kernel address
```

### The Vulnerability

The kernel releases pages from early boot regions but does NOT unmap them from the kernel virtual address space:

```
Released regions that remain mapped:
  [rodata_resource.end, data_resource.start]
  [__init_begin, __init_end]
  [__smp_locks, __smp_locks_end]
  [_brk_end, hpage_align(__end_of_kernel_reserve)]
```

Userspace can `mmap()` these addresses and write ROP chains that remain valid kernel pointers.

### Implementation

```c
#define PAYLOAD_SPRAY_PAGES 0x10

void nperm_spray(void *payload, size_t payload_size) {
    // Drain memory to increase chance of getting pages from target regions
    pgvAdd(1, 9, 0x610);  // proprietary drain method

    for (int i = 0; i < PAYLOAD_SPRAY_PAGES; i++) {
        void *addr = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE,
                          MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        memcpy(addr, payload, payload_size);  // Spray ROP chain
    }

    pgvDel(1);  // Release drain allocations
}
```

### Relevance to Angband

NPerm solves the "where to place the payload" problem by using kernel image areas that are always mapped. Combined with KASLR base leak (which is easier to obtain than heap leaks), this enables:
- Placing ROP chains at predictable addresses
- Bypassing heap randomization
- Simplifying LL_ATK exploitation (payload placement becomes deterministic)

**Status**: NOT IMPLEMENTED in angband primitives.

---

## 3. Kernel One Gadget — eBPF JIT Compiler Exploitation

**Source**: CVE-2025-21700 (DRR qdisc UAF), $82k payout  
**Authors**: Google kernelCTF submission

### Technique

The eBPF JIT compiler transforms eBPF bytecode into native x86-64 instructions. When certain eBPF programs are JIT-compiled, they produce "one-gadget"-like instruction sequences that can serve as ROP gadgets or code execution primitives:

```
eBPF bytecode → JIT compiler → native code in kernel text section
                                    │
                                    ├── mov eax, 0; ret
                                    ├── push rbp; mov rbp, rsp; ...
                                    └── Complex sequences usable as gadgets
```

### Key Capabilities

1. **Bypasses `bpf_jit_harden=1/2`**: The JIT hardening only randomizes the instruction layout; the generated instruction sequences themselves are still exploitable as gadgets.

2. **Bypasses module KASLR**: With 97% success rate, the technique can determine the eBPF JIT buffer address in the kernel, enabling reliable jumps into controlled code.

3. **Creates "one-shot" execution**: A single jump to a carefully chosen offset in the JIT buffer triggers a chain of useful operations, similar to libc's `one_gadget` in userspace exploitation.

### How It Works

1. **Load a carefully crafted eBPF program**: The program's bytecode, when JIT-compiled, produces a specific sequence of native instructions at a known offset in the JIT buffer.

2. **Trigger JIT compilation**: Load the program into the kernel via `bpf(BPF_PROG_LOAD, ...)`.

3. **Leak the JIT buffer address**: Use residual data reads or side channels to determine where the JIT buffer is located in kernel memory.

4. **Jump to the gadget**: When the exploit hijacks a function pointer, redirect it to the JIT buffer at the offset containing the desired gadget.

### How the JIT Gadgets Work

The eBPF JIT compiler translates BPF bytecode into native x86-64 instructions stored in a kernel-allocated buffer. The JIT emits sequences like:

```
; BPF_MOV64_IMM(BPF_REG_0, value)  →  mov rax, imm64     OR  xor eax, eax (when imm64=0)
; BPF_EXIT_INSN()                  →  leave; ret          OR  jmp epilogue
; BPF_MOV64_REG(BPF_REG_1, BPF_REG_0) → mov rdi, rax
; BPF_CALL (helper_function)       →  call [rbx+offset]   (indirect via helper dispatch table)
; BPF_JMP_A(offset)                →  jmp offset
```

The key insight: the JIT buffer contains **native code sequences at predictable offsets** produced by the JIT compiler, not by the BPF bytecode author. By studying the JIT's code generation patterns, attackers can locate instruction sequences that serve as useful ROP gadgets (e.g., `mov rdi, [rbp-8]; call *%rax` or stack adjustment + function call sequences). These JIT-emitted sequences form the "one gadget" — a single jump target that chains through useful primitives through the JIT's native instruction layout.

This bypasses CFI/FineIBT because the JIT buffer resides in kernel executable memory and the control flow through it is intra-buffer (no indirect call across module boundaries).

### Relevance to Angband

The perf_ring_uaf and io_uring_uaf exploits both target function pointers. If the kernel's CFI enforcement blocks direct hijack, Kernel One Gadget provides an alternative: instead of jumping to `commit_creds` directly, jump to a JIT gadget that performs the same operation through the eBPF JIT's allowed call graph.

This technique is particularly useful for:
- Bypassing IBT/FineIBT (the JIT buffer may be on a different hash than sensitive kernel functions)
- Providing "safe" indirect call targets when direct `commit_creds` is blocked by CFI
- Enabling code execution without needing exact ROP gadget addresses (the JIT buffer's layout is predictable)

---

## 4. RBTree Pointer Copy Primitive → Page-UAF

**Source**: CVE-2025-38001 (HFSC eltree), $82k payout  
**Authors**: Google kernelCTF submission

### Technique

A double-insertion into a Linux kernel RBTree creates a **pointer copy primitive**: the kernel copies a pointer from one RBTree node to another during rebalancing. When combined with a page-level UAF, this enables:

```
Stage 1: Double-insert → RBTree rebalance → pointer copy
         (kernel copies PTE pointer from Node A to Node B)

Stage 2: Page-UAF → freed page with stale PTE entries
         (freed page contains page table entries we can still modify)

Stage 3: signalfd credential overwrite
         (PTE entries → physical pages → overwrite struct cred)
```

### Mechanism

1. **RBTree double-insertion**: A bug in the HFSC scheduler allows the same node to be inserted twice into an RBTree. During the second insertion, rebalancing rotations copy pointers between nodes.

2. **Pointer copy creates aliasing**: The copied pointer now exists in two RBTree nodes that can be independently freed. Freeing one node leaves the pointer active in the other.

3. **Page-level UAF**: The duplicated pointer points to a page table entry. When the page is freed (via `put_page` or similar), the PTE still exists in the RBTree node.

4. **signalfd escalation**: The freed page is reallocated by another kernel subsystem (e.g., `signalfd` creates signal structures on the same page). The stale PTE enables writing to these structures, ultimately overwriting process credentials.

### Why This Matters

Unlike msg_msg-based reclaim (which requires knowing exact struct layouts and offsets), the RBTree pointer copy works at the **page granularity** — entire 4KB pages are aliased and can be corrupted. This is more robust against randomization and works across different kernel builds.

### Relevance to Angband

The vulnerable kernel module (`vuln_drill`) and the CVE targets all use heap-based objects. If any CVE involves RBTree operations (common in network schedulers like HFSC, QFQ, SFQ), the pointer copy primitive is applicable. Even for non-RBTree CVEs, the **page-UAF → signalfd** pattern is reusable:

```
Any UAF → page-level reclaim → signalfd structures → cred overwrite → root
```

---

## 5. signalfd Credential Overwrite Pattern

**Source**: CVE-2025-38001, CVE-2025-37752, CVE-2025-21756  
**Used in**: Multiple kernelCTF winning exploits

### Pattern

```
UAF / OOB Write
    │
    v
pipe_inode_info.bufs[] corruption
    │  (write to pipe->bufs pointer)
    v
pipe_buffer.ops = fake_ops (with controlled function pointers)
    │
    v
pipe release → pipe_release() → pipe->bufs[i]->ops->release()
    │
    v
Controlled function pointer call → kernel code execution
    OR
Controlled write through fake pipe buffer → struct files corruption
    │
    v
files_struct → struct file → f_count / f_cred → struct cred overwrite
    │
    v
Process credentials modified → root
```

### Alternative: files_struct → page-UAF

```
OOB Write into pipe_inode_info
    │
    v
files_struct.fd[] corrupted → arbitrary fd table entry point
    │
    v
struct file* → f_mapping → page-UAF → signalfd_ctx → ready_list
    │
    v
signalfd_ctx.sigmask → struct cred at known offset → overwrite
    │
    v
cred.uid = cred.euid = cred.gid = cred.egid = 0 → root
```

### Why signalfd?

Signalfd structures are convenient targets because:
1. They're allocated on easily controlled slab caches
2. They contain structures that are at predictable offsets from `struct cred`
3. The signal notification mechanism provides a deterministic trigger for checking exploitation success
4. Multiple kernelCTF exploits have validated this technique

### Relevance to Angband

The macvlan UAF currently uses `modprobe_path` overwrite for escalation. Adding the `signalfd credential overwrite` as a fallback path would make the exploit more robust against modprobe_path-based mitigations (e.g., `kernel.modules_disabled=1` or read-only modprobe_path).

---

## 6. DirtyCred — File-Based Credential Overwrite

**Source**: CVE-2022-2602, CVE-2021-26708  
**Paper**: [DirtyCred: Escalating Privilege in Linux Kernel](https://zplin.me/papers/DirtyCred.pdf)  
**Slides**: [DirtyCred Black Hat 2022](https://i.blackhat.com/USA-22/Thursday/US-22-Lin-Cautious-A-New-Exploitation-Method.pdf)  
**Writeup**: [HardenedVault - Exploiting CVE-2021-26708 with sshd](https://hardenedvault.net/blog/2022-03-01-poc-cve-2021-26708/)

### Technique

DirtyCred exploits the kernel's credential caching mechanism by using an **arbitrary free** to free a `struct cred` from the cred_jar cache and then spraying new cred objects to reclaim the slot.

```
Arbitrary free → owner_cred freed from cred_jar → spray privileged process creds → one reclaims slot → uid=0
```

### Why It Works

1. Kernel caches freed credentials in `cred_jar` slab cache
2. `prepare_cred()` pulls from cache when available
3. `arbitrary_free` + `cred_jar_spray` = controlled credential injection
4. No function pointer hijack needed — purely data-only

### Detailed Exploit Flow (CVE-2021-26708)

```
Step 1: Allocate msg_msg at predictable address
        → Win vsock race, leak heap addr from /dev/kmsg
        → msgsnd() allocates good msg at that address

Step 2: Arbitrary-free the good msg
        → Win vsock race, overwrite msg->security
        → Failed msgsnd frees msg->security (which IS the good msg)

Step 3: Arbitrary-write via setxattr
        → setxattr allocates at good msg address
        → Overwrite target object

Step 4: Leak owner_cred address
        → msgrcv reads vsk structure content

Step 5: Arbitrary-free owner_cred
        → Win race to free the cred

Step 6: Spray privileged processes (sshd)
        → ssh connections with login completed
        → One sshd's cred reclaims the freed owner_cred slot

Step 7: Use of reclaimed cred → root privileges
```

### The sshd Trick

For reliable exploitation, use sshd as the cred spray target:
```
# sshd creates privileged processes that can be sprayed
# An ssh connection with login completed has two processes:
root  924 sshd: victim [priv]   # privileged
victim 939 sshd: victim@pts/0   # unprivileged

# Without login (just connection):
sshd 988 sshd: victim [net]     # privileged but waiting for auth
```

**Key insight**: sshd processes run as root and can be triggered by unprivileged users. The sshd process stays alive during the authentication timeout, providing a stable window for cred reclamation.

### Limitations

1. **sshd must be enabled** on the target system
2. **Arbitrary free primitive required** (not just arbitrary write)
3. **Affected by other processes** if system is heavily loaded
4. **Multiple ssh connections improve reliability** to overcome cache noise

### Variants

**File-based DirtyCred** (CVE-2022-2602):
```
1. UAF on file object → arbitrary free
2. Trigger file close → cred_jar cached cred is freed
3. Spray new file objects with controlled creds
4. Use of cred → root
```

**io_uring + DirtyCred** (CVE-2022-2602):
```
io_uring UAF → arbitrary free → cred_jar reclaim → root
```

### Relevance to Angband

DirtyCred provides a **data-only escalation path** that:
- Bypasses CFI (no control flow change)
- Works when modprobe_path is protected
- Requires arbitrary free primitive (not arbitrary write)

**Status**: Referenced in `attack-surface.md` but NOT IMPLEMENTED in primitives.

---

## 7. Pipe Object Data-Only Attack & AARW Primitive

**Sources**:
- Pumpkin Chang, 2024: [Linux Kernel Use Pipe Object to Do Data-Only Attack](https://u1f383.github.io/linux/2024/08/16/linux-kernel-use-pipe-object-to-do-data-only-attack.html)
- Alexander Popov, April 2026: [pipe_buffer Security Properties](https://a13xp0p0v.github.io/2026/04/20/pipe-buffer-experiments.html)

### Technique

Uses pipe buffers and pipe_inode_info structures to achieve data-only privilege escalation without function pointer hijack:

```
OOB Write into pipe_inode_info
    │
    ├─→ Corrupt pipe->bufs[i] pointer
    │      └─→ Write through fake pipe_buffer
    │             └─→ Corrupt files_struct.fd[]
    │                    └─→ Arbitrary struct file* access
    │                           └─→ f_cred → uid=0
    │
    └─→ Corrupt pipe_buffer.page/offset/len
           └─→ Read/write arbitrary kernel memory
```

### Enhanced Pipe Buffer AARW (a13xp0p0v 2026)

Popov's research discovered that corrupting only `pipe_buffer.page` (8 bytes) enables stable AARW:

```
Step 1: Resize pipe to allocate pipe_buffer array in target slab
        fcntl(pipe_fd[1], F_SETPIPE_SZ, PAGE_SIZE * 2) → kmalloc-96

Step 2: Write full page into pipe (initializes pipe_buffer.page)

Step 3: Corrupt pipe_buffer.page pointer to point to target kernel memory

Step 4: Read page from pipe → arbitrary kernel read via pipe_data buffer

Step 5: Modify data in userspace

Step 6: Write page back to pipe → arbitrary kernel write
```

**Key discovery**: `pipe_inode_info.tmp_page[2]` caches released page pointers. When first `pipe_buffer` is consumed, the corrupted `page` pointer is cached there, enabling the second `pipe_buffer` to use the attacker's controlled address.

### pipe_buffer Security Properties (a13xp0p0v)

| Field | Offset | Exploitation Impact |
|-------|--------|---------------------|
| `page` | 0 | Corrupt → AARW via pipe read/write |
| `offset` | 8 | Set to 0 to avoid spinlock hang in kworker |
| `len` | 12 | Controls read/write size |
| `ops` | 16 | Corrupt → control-flow hijack via pipe_release() |
| `flags` | 24 | Corrupt → Dirty Pipe (overwrite read-only files) |
| `private` | 32 | May contain additional pointers |

### Key Properties

1. **No function pointers** — purely data corruption
2. **Stable** — doesn't depend on timing
3. **KASLR-independent** — uses offset-based corruption (for data targets)
4. **CFI-resistant** — no control flow changes
5. **Cross-cache compatible** — works even with `CONFIG_RANDOM_KMALLOC_CACHES`

### Relevance to Angband

- **AARW primitive**: Replaces complex msg_msg + cross-cache for simple cases
- **Data-only escalation**: Alternative to modprobe_path when kernel write needed
- **Chrome sandbox escape**: Works from restricted environments via AF_UNIX sockets

**Status**: PRIMITIVE_CANDIDATE in angband. Implement as `pipe_aarw` primitive.

---

## 8. ExpRace — Timer-Based Interrupt Technique

**Source**: CVE-2025-38477 (QFQ race condition)  
**Authors**: Google kernelCTF submission

### Technique

ExpRace exploits kernel interrupt timing to widen race condition windows in exploit scenarios:

```
Standard race window:         │█│  (few microseconds)
ExpRace-extended window:      │████████│  (tens of microseconds)
```

By precisely controlling when interrupts fire relative to critical kernel operations, ExpRace can:
1. **Extend the race window**: Hold an interrupt pending so a critical section is deferred, widening the window for concurrent operations
2. **Synchronize threads**: Coordinate multiple exploit threads to operate within the same RCU grace period
3. **Defeat heuristics**: Bypass kernel race-detection mechanisms that trigger on "too many" close()/open() pairs

### Mechanism

```
1. Arm a high-resolution timer interrupt for a precise future timestamp
2. The interrupt fires during the kernel's critical section
3. Interrupt handling delays the kernel's cleanup code
4. Meanwhile, the exploit thread reallocates the freed memory
5. When execution resumes, the kernel operates on the reallocated (controlled) data
```

### Relevance to Angband

The timerfd UAF requires `clock_was_set()` to traverse the `cancel_list` while `timerfd_ctx` entries are on it. ExpRace could potentially widen the window between `timerfd_remove_cancel()` and `kfree_rcu()`, making the race winnable.

---

## 9. CARDSHARK — Heap Alignment Technique

**Source**: CVE-2025-38477 (QFQ race condition)  

### Technique

CARDSHARK pre-positions heap objects at specific alignments within slab pages by controlling allocation order and sizes:

```
Slab page before CARDSHARK:
  [obj1|obj2|obj3|obj4|obj5|obj6|  FREE  |obj8|...]

Slab page after CARDSHARK:
  [drain|drain|drain|FREE at offset 0x100|obj7|obj8|...]
                       ↑
                  Precisely positioned free slot
```

This ensures that when a freed object is reclaimed, the controlled data lands at predictable offsets relative to other kernel objects. Combined with cross-cache attacks, this enables writing into victim objects that are in different slab caches.

### Relevance to Angband

The macvlan UAF uses slab drain cycling for similar alignment. Formalizing CARDSHARK would make the alignment more precise and reliable, reducing the need for brute-force offset scanning.

---

## 10. Prefetch KASLR Leak

**Source**: CVE-2025-21756 (vsock UAF)  

### Technique

The prefetch instruction (`prefetcht0`, `prefetcht1`, `prefetcht2`) can leak information about memory layout through timing differences:

1. Attempt to prefetch a kernel address
2. If the address is mapped → cache hit, fast
3. If the address is unmapped → cache miss, slow (or fault, but prefetch doesn't fault on invalid)

Timing the difference reveals which addresses are mapped, effectively leaking the kernel's virtual memory layout without requiring `kptr_restrict=0`.

### Implementation

```c
static uint64_t probe_address(unsigned long addr) {
    uint64_t start = rdtsc();
    asm volatile("prefetcht0 (%0)" :: "r"(addr));
    uint64_t end = rdtsc();
    return end - start;  // low = mapped, high = unmapped
}
```

### Relevance to Angband

The current KASLR bypass in `primitives/kaslr.c` uses kallsyms (needs `kptr_restrict=0`) or side-channel timing (probes syscall entry). Adding a prefetch-based leak would provide a third option that works with `kptr_restrict>0` without needing syscall timing variations.

---

## 10b. Linear Mapping KASLR Bypass (ARM64)

**Source**: Seth Jenkins, Project Zero, November 2025  
**URL**: `googleprojectzero.blogspot.com/2025/11/defeating-kaslr-by-doing-nothing-at-all.html`

### Technique

On ARM64, the kernel's linear mapping is **not randomized** due to `CONFIG_MEMORY_HOTPLUG` requirements:

```
PHYS_OFFSET = 0x80000000 (always static on ARM64)
PAGE_OFFSET = 0xffffff8000000000

virt_to_phys(virt) = (virt & ~PAGE_OFFSET) + PHYS_OFFSET
phys_to_virt(phys) = ((phys - PHYS_OFFSET) | PAGE_OFFSET)
```

Additionally, the bootloader decompresses the kernel at a **static physical address** (0x80010000 on Pixel).

### Statically Computable Addresses

```
kernel_base_phys = 0x80010000  (bootloader, not randomized)
modprobe_path_virt = 0xffffff8001ff2398  (statically calculable)

# Example: Calculate modprobe_path virtual address
offset = modprobe_path - _text  (from kallsyms on any boot)
modprobe_path_virt = 0xffffff8000010000 + offset
```

### Limitations

- Only works on ARM64 targets (Pixel, Android devices)
- `.text` sections are not executable from linear mapping
- `.data` sections are rw — data-only attacks work fine
- Physical address randomization on some devices defeats this

### Relevance to Angband

For ARM64 Android targets:
- **No leak stage needed** — KASLR base is static
- Can directly calculate `modprobe_path` address
- Reduces exploit chain complexity significantly

**Integration**: Add ARM64 target detection to `primitives/kaslr.c` with fallback to existing methods.

---

## 11. Cross-Cache Attacks

**Source**: CVE-2025-21756 (vsock UAF), CVE-2025-21700 (DRR qdisc)

### Technique

When a freed object's original slab cache has been drained and the page returned to the buddy allocator, the page can be reallocated to a **different** slab cache:

```
kmalloc-256 page → object freed → slab drained → page returned to buddy
                                                        │
                                                        v
                                        page reallocated to kmalloc-512 cache
                                                        │
                                                        v
                            Object at same physical address, different cache context
```

This enables attacking objects that would normally be isolated in different caches.

### Mechanism

1. Free many objects in cache A → slab page becomes empty
2. Page returned to buddy allocator
3. Allocate objects in cache B → buddy allocator gives the same physical page to cache B
4. Stale pointer in cache A now points to cache B objects
5. Write through stale pointer → corrupts cache B objects

### Relevance to Angband

If `CONFIG_RANDOM_KMALLOC_CACHES` is enabled (harder to predict which cache an object lands in), cross-cache attacks provide a fallback for reaching object types that aren't in the expected cache.

---

## 12. FALLOC_FL_PUNCH_HOLE — Race Window Extension

**Source**: See `docs/vkb.md` → FALLOC_FL_PUNCH_HOLE for full reference.

### Technique

`fallocate(FALLOC_FL_PUNCH_HOLE)` on `/dev/shm` files can deliberately slow kernel memory accesses, widening race condition windows:

```
Thread A: Kernel accesses user memory (copy_from_user / get_user)
          │
          v
Page fault (user page in tmpfs / shmem)
          │
          v
shmem_fault() → reads from backing file (shmem/tmpfs)
          │
          v
If page was punched out via FALLOC_FL_PUNCH_HOLE:
  → shmem_getpage_gfp() must reallocate and read from disk
  → DELAY of hundreds of microseconds
          │
          v
During this delay, Thread B completes the race operation
```

### When to Use

- Alternative to userfaultfd when `CONFIG_USERFAULTFD=n`
- Alternative to FUSE when FUSE mounts are restricted
- Works on tmpfs/shmem-backed memory (no sudo needed)

### Comparison with Other Race Window Techniques

| Technique | Requires Config | Privileged? | Delay (approx) |
|-----------|----------------|-------------|----------------|
| userfaultfd | `CONFIG_USERFAULTFD=y` | No | 1-100ms |
| FUSE | `CONFIG_FUSE_FS=y` | No (if FUSE allowed) | 10-100ms |
| FALLOC_FL_PUNCH_HOLE | tmpfs (always available) | No | 100-500μs |
| MADV_DONTNEED | Always | No | 50-200μs |
| ExpRace (timer interrupt) | Always | No | 10-50μs |

---

## 13. KernelSnitch — Heap KASLR Leak

**Source**: See `docs/vkb.md` → KernelSnitch for full reference.

### Technique

KernelSnitch is a **timing side-channel attack** that leaks kernel heap addresses of exploitation-relevant allocations (msg_msg, pipe_buffer). Key properties:

1. **Non-destructive**: Does not crash or corrupt the kernel
2. **Works on Android**: Tested on multiple Android kernels
3. **Leaks object addresses**: Where msg_msg / pipe_buffer objects land in kernel heap
4. **Enables precise spray targeting**: Knowing exact kernel heap layout eliminates blind spraying

### Exploitation Impact

```
Without heap leak:    Spray 512 msg_msg objects → hope one lands on freed target
With KernelSnitch:    Know exact address → spray 1 targeted msg_msg → guaranteed hit
```

This transforms probabilistic sprays into deterministic ones, dramatically increasing exploit reliability.

### Relevance to Angband

The current exploit templates use blind sprays with brute-force offset scanning. Integrating KernelSnitch would:
1. Eliminate the PTE pattern page scanning in the macvlan exploit
2. Enable direct targeting of the freed object without 16-offset iteration
3. Make timerfd/perf/io_uring exploits more reliable by knowing exact reclaim addresses

---

## 14. Out-of-Cancel — Vulnerability Class from Workqueue APIs

**Source**: See `docs/vkb.md` → Out-of-Cancel for full reference.

### Technique

Kernel code that uses `cancel_work_sync()` / `cancel_delayed_work_sync()` incorrectly can create complex race conditions:

```
Pattern:
  Thread A: do_work() → schedule_work(&w)
  Thread B: cancel_work_sync(&w)  ← waits for work to finish
  Thread A: [work completes, frees resources]
  Thread C: [accesses freed resources through stale reference]
```

The key insight: `cancel_work_sync()` guarantees the work won't run AFTER the call, but doesn't protect against work that was already running when cancel was called. Misuse of this API in network subsystem code creates UAF conditions.

### Relevance to Angband

This is a **bug-hunting technique** rather than an exploitation primitive. Understanding Out-of-Cancel patterns helps identify UAF candidates in kernel subsystems that use workqueues (network, block, USB, etc.). If Angband's `VulnAnalyzer` can detect `cancel_work_sync` patterns in patch diffs, it can classify new CVEs that exploit this pattern.

---

## 15. CVE-2025-38617 — "A Race Within A Race"

**Source**: See `docs/vkb.md` → CVE-2025-38617 for full reference.

### Technique

Exploitation of a packet sockets UAF that **bypasses both CONFIG_RANDOM_KMALLOC_CACHES and CONFIG_SLAB_VIRTUAL**. Key innovations:

1. **Race-within-a-race**: Two nested race conditions — the first extends the UAF window, the second achieves exploitation within it
2. **SLAB_VIRTUAL bypass**: Uses physmap spraying to reach objects across virtual memory remapping
3. **RANDOM_KMALLOC_CACHES bypass**: Cross-cache technique that doesn't depend on cache prediction

### Relevance to Angband

This demonstrates that even the strongest kernel mitigations can be bypassed with sophisticated race management. The physmap spray technique is particularly relevant — it provides an alternative to slab-based spraying when slab randomization is enabled.

---

## 16. SLUBStick — Arbitrary Read/Write from Limited Heap Bug

**Source**: See `docs/vkb.md` → SLUBStick for full reference.

### Technique

SLUBStick transforms a **limited heap vulnerability** (OOB read, heap overflow, or similar) into a **full arbitrary read/write primitive** using a timing side-channel attack on the SLUB allocator.

```
Without SLUBStick (limited bug → uncertain outcome):
  OOB read → partial info leak → need additional bugs for full exploit

With SLUBStick (limited bug → arbitrary r/w):
  OOB read → flush+reload timing → determine heap layout →
  controlled allocations → cross-cache reclaim → arbitrary read/write
```

### Mechanism

1. **Timing Side-Channel Setup**:
   - Allocate many objects of the same kmalloc cache
   - Flush cache lines for target memory region
   - Re-access allocations, measure load time (flush+reload)
   - Occupied vs. free slots show measurable latency difference (~100-200 cycles)

2. **Freelist Manipulation**:
   - Controlled allocations/deallocations let attacker predict next allocation address
   - Force SLUB to place target object at desired cache line

3. **Cross-Cache Attack with Determinism**:
   - Drain source cache → force slab page return to buddy allocator
   - Allocate from target cache → buddy reuses freed page
   - Now UAF pointer in cache A can read/write objects in cache B
   - ~90% success rate (vs ~5% for naive cross-cache)

4. **Arbitrary Read/Write**:
   - From cross-cache position, read/write any kernel object on the reused page
   - Corrupt target object → privilege escalation

### Why ~90% Success Rate

Naive cross-cache attacks fail because:
- Physical page placement in buddy is probabilistic
- Cache line sharing between different objects complicates layout

SLUBStick succeeds because:
- Timing channel reveals exact object layout before exploitation
- Controlled allocations let attacker place objects precisely
- Cross-cache reuse becomes deterministic, not probabilistic

### Key Advantage: No ROP Needed

SLUBStick achieves **arbitrary read/write purely via data corruption**:
- No function pointer hijack needed
- No ROP chain needed
- CFI cannot block data-only attacks
- Combine with Pattern A (modprobe_path) for trivial escalation

### Relevance to Angband

SLUBStick is most relevant for CVEs where:
- Bug is a **limited heap read/write** (not a full UAF)
- Object size makes cross-cache reclaim feasible
- Kernel has `CONFIG_RANDOM_KMALLOC_CACHES` or `CONFIG_SLAB_VIRTUAL` enabled

**Integration path**: SLUBStick would replace the naive cross-cache approach in Angband's groom stage for limited-heap-bug CVEs. The timing side-channel would be implemented as a new `leak` stage primitive.

---

## 17. Dirty Pagetable — Page-Level Cross-Cache Write

**Source**: CVE-2026-23209 (macvlan UAF)  
**Implementation**: `primitives/dirty_pagetable.c`

### Technique

Dirty Pagetable exploits the kernel's page table structure to achieve arbitrary kernel write by corrupting PTE (Page Table Entry) mappings. This technique bypasses `CONFIG_RANDOM_KMALLOC_CACHES` because it operates at the hardware level (page tables), not the slab allocator level.

```
Standard cross-cache:    UAF → slab reclaim → write to wrong cache object
Dirty Pagetable:        UAF → PTE redirect → write to ANY kernel address
```

### Mechanism

1. **Freed object on known physical page**: After UAF, the freed kernel object resides on a known physical page (4KB alignment)

2. **Return page to buddy allocator**: Drain all objects on the same slab page → page returned to buddy allocator

3. **Spray PTE pages**: Allocate many PTE pages via `mmap(MAP_ANONYMOUS|MAP_POPULATE)`. Each PTE page maps different physical pages.

4. **Find PTE mapping target physical page**: Use `/proc/self/pagemap` to scan PTE spray regions and find which virtual address maps the target physical page

5. **Corrupt PTE entry**: Modify the PTE entry to point the virtual address at a different physical address (e.g., `modprobe_path`)

6. **Write via virtual address**: Writing to the userspace virtual address now writes to the redirected physical address

### Implementation (`primitives/dirty_pagetable.c`)

```c
int pte_spray_init(void);           // Allocate PTE spray pages
void pte_spray_cleanup(void);       // Free spray pages
unsigned long pte_lookup_phys(void *vaddr);  // Get physical addr from pagemap
int pte_overwrite(unsigned long target_phys, const void *data,
                  size_t len, unsigned long offset);
void *pte_get_addr(int idx);        // Get PTE page virtual address
int pte_get_count(void);            // Get number of PTE pages
unsigned long pte_get_page_phys(int idx);  // Get PTE page physical address
```

### Relevance to Angband

The macvlan UAF (CVE-2026-23209) uses Dirty Pagetable to achieve `modprobe_path` overwrite:

1. Freed `net_device` + `macvlan_dev` on a physical page
2. Drain slab → page to buddy → PTE spray reclaims page
3. PTE entry modified to map the page at `modprobe_path`'s physical address
4. Write fake `macvlan_dev` with `pcpu_stats = modprobe_path - 8`
5. Packet reception → `u64_stats_inc(&pcpu_stats->rx_packets)` writes to `modprobe_path`

**NOTE**: This is the **only technique in the framework claiming to achieve privilege escalation**, but the implementation is incomplete. See `docs/CVE-2026-23209-analysis.md` for details.

### Key Advantage: KASLR-Independent

Unlike heap spraying which depends on knowing cache sizes and object layouts, Dirty Pagetable works because:
- Physical page addresses are always 4KB-aligned
- PTE entries are directly writable via userspace
- The kernel's own page table walking code follows the corrupted PTE

---

## 18. BPF Verifier Abuse — Limited Write to Kernel R/W

**Source**: CVE-2025-40364  
**URL**: [kernelCTF CVE-2025-40364](https://github.com/google/security-research/tree/master/pocs/linux/kernelctf/CVE-2025-40364_lts_cos_mitigation)

### Technique

Uses cross-cache attacks to reclaim BPF `array_map` pages, then exploits the BPF verifier to turn a **single limited UAF write** into a **stable full kernel read/write primitive**.

```
1. Cross-cache UAF → reclaim array_map pages with controlled data
2. Single UAF write breaks verifier assumption → unlock map as writable
3. Use unlocked map to read/write arbitrary kernel memory
```

### Limitations

1. Requires `unprivileged_bpf_disabled == 0` (unprivileged BPF enabled)
2. Requires kernel version < c4c84f6fb2c4dc4c0f5fd927b3c3d3fd28b7030e (map_freeze restriction)

### Relevance to Angband

This is an alternative escalation path when:
- Limited write primitive exists but not arbitrary write
- BPF subsystem is available
- Provides stable kernel read/write without function pointer hijack

**Status**: NOT IMPLEMENTED in angband primitives.

---

## Technique Selection Matrix

| Technique | CVE-Agnostic? | Needs Heap Leak? | Needs KASLR Bypass? | CFI-Resistant? | Difficulty |
|-----------|---------------|-----------------|---------------------|----------------|------------|
| LL_ATK | No (list-based CVEs) | **No** | Yes | Maybe | ★★★★☆ |
| NPerm | **Yes** | No | No | **Yes** | ★★☆☆☆ |
| Kernel One Gadget | **Yes** | No | Yes | **Yes** | ★★★★☆ |
| RBTree Pointer Copy | No (RBTree CVEs) | No | Yes | **Yes** | ★★★★★ |
| signalfd Credential | **Yes** | Depends on UAF type | Yes | N/A (data-only) | ★★★☆☆ |
| **DirtyCred** | **Yes** | Needs arbitrary free | No | **Yes** (data-only) | ★★★☆☆ |
| **Pipe AARW** | **Yes** | No | No | **Yes** (data-only) | ★★★☆☆ |
| **Linear Mapping KASLR** | No (ARM64 only) | **No** | N/A (static base) | **Yes** | ★★☆☆☆ |
| ExpRace | No (race-based CVEs) | No | Yes | N/A | ★★★★☆ |
| CARDSHARK | **Yes** | No | No | **Yes** | ★★★☆☆ |
| Prefetch KASLR | **Yes** | N/A | N/A (IS the bypass) | **Yes** | ★★☆☆☆ |
| FALLOC_FL_PUNCH_HOLE | No (race-based CVEs) | No | Yes | N/A | ★★☆☆☆ |
| KernelSnitch | **Yes** | N/A (IS the leak) | Yes | **Yes** | ★★★☆☆ |
| Cross-Cache | **Yes** | No | Yes | **Yes** | ★★★★☆ |
| SLUBStick | **Yes** | No | Yes | **Yes** | ★★★★★ |
| Physmap Spray | **Yes** | No | Yes | **Yes** | ★★★★★ |
| Dirty Pagetable | **Yes** | No | Yes | **Yes** | ★★★☆☆ |
| BPF Verifier Abuse | No (BPF CVEs) | No | Yes | **Yes** | ★★★★☆ |
| modprobe_path | **Yes** | No | Yes | N/A (data-only) | ★★☆☆☆ |

---

## Implementation Priority for Angband

| Priority | Technique | Reason |
|----------|-----------|--------|
| P0 | **Pipe AARW** | a13xp0p0v validated, strong primitive, simple to implement |
| P0 | signalfd Credential | Already implemented in 3 kernelCTF winners, relatively simple |
| P0 | DirtyCred | File-based cred overwrite, widely applicable |
| P0 | Linear Mapping KASLR | Trivial bypass for ARM64, eliminates leak stage |
| P0 | Prefetch KASLR | Adds third KASLR bypass option, simple to implement |
| P0 | KernelSnitch | Eliminates blind spraying, dramatically improves reliability |
| P1 | FALLOC_FL_PUNCH_HOLE | Race window extension without userfaultfd dependency |
| P1 | CARDSHARK | Improves spray reliability for all CVEs |
| P1 | Cross-Cache | Needed for CONFIG_RANDOM_KMALLOC_CACHES |
| P1 | SLUBStick | Converts limited heap bugs to arbitrary r/w, needed for OOB-class CVEs |
| P1 | NPerm | Simplifies LL_ATK by solving payload placement, works with KASLR base leak only |
| P1 | BPF Verifier Abuse | Alternative escalation path for limited-write CVEs |
| P2 | Kernel One Gadget | CFI bypass for func ptr hijack |
| P2 | LL_ATK | Alternative timerfd exploitation path |
| P2 | Physmap Spray | CONFIG_SLAB_VIRTUAL bypass |
| P3 | RBTree Pointer Copy | Requires finding RBTree double-insertion CVE |
| P3 | ExpRace | Needs race-based CVE with interrupt timing |
