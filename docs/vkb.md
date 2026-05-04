# Vulnerability Knowledge Base (VKB)

Central index of all ring 0 exploitation references used by the Angband framework. Each entry contains a title, URL/source, and relevance note. Use this as the single source of truth for external references.

For in-framework documents, see `docs/index.md`.

---

## Comprehensive Bibliographies

### Linux Kernel Exploitation Bibliography
**Source**: [@andreyknvl](https://x.com/andreyknvl)  
**URL**: [andreyknvl/Linux-Kernel-Exploitation](https://github.com/andreyknvl/Linux-Kernel-Exploitation)  
**Original**: Follow [@andreyknvl](https://x.com/andreyknvl) on X, [@xairy@infosec.exchange](https://infosec.exchange/@xairy) on Mastodon, or [@andreyknvl](https://bsky.app/profile/andreyknvl.bsky.social) on Bluesky  
**Content**: 1082+ references organized by: Books, Techniques (Exploitation / Protection Bypasses), Vulnerabilities (Info-leaks / LPE / RCE / Other), Finding Bugs, Defensive, Exploits, Tools (Fuzzers / Assorted), Practice (Workshops / CTF Tasks / Other Tasks / Playgrounds / Infrastructure), Misc  
**Relevance**: Primary bibliography for kernel exploitation research. Updated bimonthly.

### Google kernelCTF Submission Style Guide
**Source**: Google Security Team  
**URL**: [google/security-research - kernelCTF](https://github.com/google/security-research/tree/master/security-research/kernelctf)  
**Content**: 1244-line guide covering exploit structure, function naming conventions (`setup_`, `vuln_`, `spray_`, `fake_` prefixes), heap grooming methodology, race condition techniques, verification requirements  
**Relevance**: Defines the standard methodology for kernelCTF-winning exploit construction. Used as the reference for Angband's 7-stage pipeline.

---

## kernelCTF Winning Submissions (60+ CVEs)

**Source**: Google Security Team  
**URL**: [google/security-research - kernelCTF PoCs](https://github.com/google/security-research/tree/master/pocs/linux/kernelctf)  
**Coverage**: 60+ CVE directories with full exploit code, write-ups, and mitigation status

Notable submissions (see individual directories for full list):

| CVE | Bug Class | Notable Technique | Mitigation Status |
|-----|-----------|-------------------|------------------|
| CVE-2023-0461 | UAF | ipc/sem setxattr | Mitigated |
| CVE-2023-31436 | UAF |QFQ scheduler | Mitigated |
| CVE-2023-32233 | UAF | netfilter nftables | Mitigated |
| CVE-2023-3609 | UAF | DCCP | Mitigated |
| CVE-2023-3611 | UAF | UML | Mitigated |
| CVE-2023-3776 | UAF | xfrm | Mitigated |
| CVE-2023-3777 | UAF | netfilter | Mitigated |
| CVE-2023-4004 | UAF | SGX | Mitigated |
| CVE-2023-4015 | UAF | vsock | Mitigated |
| CVE-2023-4147 | UAF | UML | Mitigated |
| CVE-2023-4206 | OOB | SFQ | Mitigated |
| CVE-2023-4207 | OOB | SFQ | Mitigated |
| CVE-2023-4208 | OOB | SFQ | Mitigated |
| CVE-2023-4244 | UAF | nftables | Mitigated |
| CVE-2023-4569 | UAF | nftables | Mitigated |
| CVE-2023-4622 | UAF | netfilter | Mitigated |
| CVE-2023-4623 | UAF | netfilter | Mitigated |
| CVE-2023-4921 | UAF | vsock | Mitigated |
| CVE-2023-5197 | UAF | io_uring | Mitigated |
| CVE-2024-1085 | UAF | nf_tables | Mitigated |
| CVE-2024-1086 | OOB | netfilter | Mitigated |
| CVE-2025-21700 | UAF | DRR-qdisc | Unmitigated |
| CVE-2025-21756 | UAF | vsock | Unmitigated |
| CVE-2025-37752 | OOB | SFQ | Unmitigated |
| CVE-2025-38477 | Race | QFQ | Unmitigated |
| CVE-2025-38617 | UAF | packet sockets | Unmitigated |
| CVE-2025-38236 | UAF | AF_UNIX OOB | Fixed 6.9.8 |
| CVE-2024-50264 | UAF | vsock (race) | Pwnie Award 2025 |

---

## Specific Exploitation Techniques

### SLUBStick: Arbitrary Memory Writes through Practical Software Cross-Cache Attacks
**Source**: Lukas Maar et al., IAIK / USENIX Security 2024  
**URL**: `iaik.github.io/slubstick/`  
**Paper**: `stefangast.eu/papers/slubstick.pdf`  
**Code**: `github.com/IAIK/slubstick`  
**Key insight**: ~90% success rate cross-cache attack using timing side-channel. Converts limited heap bugs (OOB read/write) into arbitrary read/write primitives.  
**Relevance**: Primary technique for limited-heap-bug CVEs. Referenced in `docs/novel-techniques.md` (technique #13) and `docs/bug-class-taxonomy.md`.

### pipe_buffer Security Properties & AARW Primitive
**Source**: Alexander Popov, April 2026  
**URL**: `a13xp0p0v.github.io/2026/04/20/pipe-buffer-experiments.html`  
**Code**: `github.com/a13xp0p0v/kernel-hack-drill`  
**Key findings**:
- Corrupting `pipe_buffer.page` (8 bytes) enables arbitrary address read/write via pipe
- `pipe_buffer.flags` corruption enables Dirty Pipe attack (overwrite read-only files)
- Corrupting `pipe_buffer.ops` enables control-flow hijack via `pipe_release()`
- Corrupting `page` + `splice()` enables stable AARW without ops corruption
- `pipe-user-pages-soft` limit (default 16384) affects spray behavior
- Cross-cache attacks via `pipe_buffer` are stable even with `CONFIG_RANDOM_KMALLOC_CACHES`
**Relevance**: Provides strongest generic AARW primitive. Angband primitive candidates: `pipe_aarw`, `pipe_dirtypipe`.

### Linear Mapping KASLR Bypass (ARM64 / Android)
**Source**: Seth Jenkins, Project Zero, November 2025  
**URL**: `googleprojectzero.blogspot.com/2025/11/defeating-kaslr-by-doing-nothing-at-all.html`  
**Key findings**:
- On ARM64, `PHYS_OFFSET` is always 0x80000000 (not randomized)
- Bootloader decompresses kernel at static physical address 0x80010000 (Pixel)
- Kernel virtual addresses can be **statically calculated** from physical addresses
- Formula: `virt = (phys - 0x80000000) | 0xffffff8000000000`
- `.data` sections are rw but `.text` is not executable
- Works on Pixel and devices with non-randomized kernel placement
**Relevance**: Trivial KASLR bypass for ARM64 Android targets. Eliminates need for leak stage on these targets.

### MSG_OOB UAF (CVE-2025-38236)
**Source**: Jann Horn, Project Zero, August 2025  
**URL**: `googleprojectzero.blogspot.com/2025/08/from-chrome-renderer-code-exec-to-kernel.html`  
**Bug**: Dangling `oob_skb` pointer in `unix_stream_recv_urg()` after AF_UNIX socket OOB handling  
**Primitive**:
- Read: `copy_to_user()` via `recv(MSG_OOB|MSG_PEEK)` - arbitrary kernel read
- Write: Increment of 4 bytes at offset 0x44 (adds 4GB to pointer/length)
- Chaining: Page table corruption via pipe buffers + `CONFIG_RANDOMIZE_KSTACK_OFFSET`
**Status**: Fixed in Linux 6.9.8  
**Relevance**: New AF_UNIX primitive for Chrome renderer→kernel escapes.

### KernelSnitch: Heap Layout KASLR Leak via Timing Side-Channel
**Source**: Lukas Maar, Apr 2026  
**URL**: `github.com/lukasmaar/kernelsnitch`  
**Article**: `lukasmaar.github.io/posts/heap-kaslr-leak/index.html`  
**Key insight**: Flush+reload timing reveals which heap slots are occupied. Enables deterministic spray targeting instead of blind 512-object spray.  
**Relevance**: Provides heap address leak without kptr_restrict bypass. Referenced in `docs/novel-techniques.md` (technique #10).

### LL_ATK: Linked List Attack (CVE-2025-38477 / QFQ)
**Source**: Google kernelCTF winning submission, $82k payout  
**URL**: [google/security-research - CVE-2025-38477](https://github.com/google/security-research/tree/master/pocs/linux/kernelctf/CVE-2025-38477)  
**Key insight**: List unlink operations write to `prev->next` and `next->prev` — through type confusion, these become function pointer writes without needing a heap address leak.  
**Relevance**: Alternative exploitation path for list-based UAFs (timerfd, etc.). Referenced in `docs/novel-techniques.md` (technique #1).

### Kernel One Gadget: eBPF JIT for CFI Bypass
**Source**: Google kernelCTF winning submission (CVE-2025-21700 / DRR)  
**URL**: [google/security-research - CVE-2025-21700](https://github.com/google/security-research/tree/master/pocs/linux/kernelctf/CVE-2025-21700)  
**Key insight**: eBPF JIT compiler emits predictable native instruction sequences that serve as ROP gadgets. Bypasses CFI by targeting JIT-emitted code paths.  
**Relevance**: CFI bypass for function-pointer-hijack exploits. Referenced in `docs/novel-techniques.md` (technique #2).

### FALLOC_FL_PUNCH_HOLE: Race Window Extension
**Source**: @linkersec  
**URL**: `faith2dxy.xyz/2025-11-28/extending_race_window_fallocate/`  
**Key insight**: `fallocate(FALLOC_FL_PUNCH_HOLE)` on `/dev/shm` files slows kernel memory accesses, widening race windows without userfaultfd dependency.  
**Relevance**: Race window extension alternative to userfaultfd. Referenced in `docs/novel-techniques.md` (technique #9).

### Out-of-Cancel: Workqueue API Misuse Pattern
**Source**: @v4bel, Mar 2026  
**URL**: `v4bel.github.io/linux/2026/03/23/ooc.html`  
**Key insight**: `cancel_work_sync()` guarantees work won't run after return, but in-flight work may still be running. Freeing resources after cancel creates UAF.  
**Relevance**: Bug-hunting pattern for identifying workqueue-based UAFs. Referenced in `docs/novel-techniques.md` (technique #11).

### CVE-2025-38617: "A Race Within A Race" — physmap + SLAB_VIRTUAL bypass
**Source**: Quang Le (@linkersec), Apr 2026  
**URL**: `blog.calif.io/p/a-race-within-a-race-exploiting-cve`  
**Key insight**: Nested race conditions bypass both `CONFIG_RANDOM_KMALLOC_CACHES` and `CONFIG_SLAB_VIRTUAL`. physmap spray provides alternative to slab-based spraying.  
**Relevance**: Shows even strongest mitigations can be bypassed. Referenced in `docs/novel-techniques.md` (technique #12).

---

## Defense & Mitigation Research

### VED — Vault Exploit Defense (HardenedVault)
**Source**: HardenedVault  
**URL**: [HardenedVault/vault_dev](https://github.com/HardenedVault/vault-dev) (contains VED PoCs with mitigation status)  
**Key mitigations**: VED msg protecting, VED pipe-buffer protecting, VED poison-cred, VED core_pattern, VED slab poisoning  
**Effectiveness**: Blocks most exploits except DirtyPipe (CVE-2022-0847); partially mitigates SLUBStick  
**Relevance**: Reference for which exploits VED blocks. Referenced in `docs/mitigations-defense.md`.

### kernel-hack-drill — Exploit Development Framework
**Source**: Alexander Popov  
**URL**: `github.com/a13xp0p0v/kernel-hack-drill`  
**Content**: Training module with UAF/OOB primitives for learning kernel exploitation. Contains PoC exploits:
- `drill_uaf_callback.c`: UAF → callback hijack → LPE
- `drill_uaf_w_msg_msg.c`: UAF → msg_msg reclaim → OOB read
- `drill_uaf_w_pipe_buffer.c`: UAF → pipe_buffer → Dirty Pipe → LPE
- `drill_uaf_w_pte.c`: Cross-cache → PTE overwrite → Dirty Pagetable → LPE
**Relevance**: Testing ground for CVE-2024-50264 exploit development. Validates cross-cache techniques on modern kernels.

### LKRG — Linux Kernel Runtime Guard
**Source**: Openwall  
**URL**: `github.com/openwall/lkrg`  
**Protections**: Credential checking, process integrity, IDT verification, self-modifying code detection  
**Limitations**: ~3-5% performance overhead; can be bypassed by corrupting LKRG's own data structures  
**Relevance**: Defense-in-depth option. Referenced in `docs/mitigations-defense.md`.

### AUTOSLAB — Slab Object Isolation
**Source**: PaX/GRsecurity  
**URL**: `grsecurity.net/how_autoslab_changes_the_memory_unsafety_game` (Zhenpeng Lin, 2021)  
**Key insight**: Isolates each `kmalloc` type into dedicated caches. **Only mitigation that kills SLUBStick** and most cross-cache attacks.  
**Status**: In active development (as of 2026), mainline upstream pending  
**Relevance**: Primary defense against SLUBStick. Referenced in `docs/mitigations-defense.md` and `docs/bug-class-taxonomy.md`.

### AUTOSLAB — Lin's Analysis
**Source**: Zhenpeng Lin  
**URL**: `grsecurity.net/how_autoslab_changes_the_memory_unsafety_game` (article)  
**Content**: Detailed explanation of how AUTOSLAB changes the memory unsafety game  
**Relevance**: Primary analysis of AUTOSLAB's impact on kernel exploitation.

### CONFIG_RANDOM_KMALLOC_CACHES / CONFIG_SLAB_VIRTUAL / TYPED_KMALLOC_CACHES
**Source**: Mainline kernel / Marco Elver patch series  
**URL**: `lore.kernel.org/linux-mm/` (Marco Elver patch series)  
**Key insight**: RANDOM_KMALLOC_CACHES provides probabilistic obstruction; SLAB_VIRTUAL breaks physmap correlation; TYPED_KMALLOC_CACHES (Clang 22) provides deterministic type-based isolation  
**Relevance**: Mitigation stack for heap exploitation. Referenced in `docs/heap-exploitation.md` and `docs/mitigations-defense.md`.

### PaX Userland Exec Bypass
**Source**: PaX Team  
**URL**: [pax.grsecurity.net/docs/pax-exec-future.txt](https://pax.grsecurity.net/docs/pax-exec-future.txt)  
**Content**: Original PaX attack paradigm framework (2003) — categorized attacks into arbitrary code injection (dead), code reuse (dying), data-only (primary)  
**Relevance**: Foundational taxonomy for understanding modern exploit design. Referenced in `docs/bug-class-taxonomy.md`.

---

## Additional Research Materials

### HardenedVault grsecurity-101-tutorials
**Source**: HardenedVault  
**URL**: `github.com/hardenedlinux/grsecurity-101-tutorials`  
**Subdirectories**:
- `threat_model/` — slubstick.md, dram_attacks.md, selinux_bypass.md, userland_exec_noexec_bypass.md  
- Individual tutorials on grsecurity features

### HardenedVault DFI Blog (Data Flow Integrity post-CFI era)
**Source**: HardenedVault  
**URL**: `hardenedvault.net/blog/` (DFI-related posts)  
**Key topics**: CFI bypasses, data-only attacks after CFI deployment, VED implementation details  
**Relevance**: Understanding defense evolution and exploitation adaptation.

---

## Reference Exploit Code (Angband-specific)

### Primitive Implementations
| File | Purpose | Source |
|------|---------|--------|
| `primitives/msg_msg.c` | msg_msg spray primitive | Angband |
| `primitives/dirty_pagetable.c` | PTE corruption for arbitrary write | Angband |
| `primitives/dirty_cred.c` | dirty_cred escalation | Angband |
| `primitives/userns.c` | Namespace setup for CAP_NET_ADMIN | Angband |
| `primitives/kaslr.c` | kallsyms + sidechannel KASLR bypass | Angband |

---

## Quick Lookup

| What you need | Go to |
|--------------|-------|
| SLUBStick paper | [iaik.github.io/slubstick](https://iaik.github.io/slubstick/) |
| KernelSnitch tool | [github.com/lukasmaar/kernelsnitch](https://github.com/lukasmaar/kernelsnitch) |
| Full CVE bibliography (1082 refs) | [andreyknvl/Linux-Kernel-Exploitation](https://github.com/andreyknvl/Linux-Kernel-Exploitation) |
| kernelCTF winning submissions | [google/security-research - kernelCTF](https://github.com/google/security-research/tree/master/pocs/linux/kernelctf) |
| VED mitigation status | [HardenedVault/vault-dev](https://github.com/HardenedVault/vault-dev) |
| AUTOSLAB analysis | [grsecurity.net/how_autoslab](https://grsecurity.net/how_autoslab_changes_the_memory_unsafety_game) |
| LKRG source | [github.com/openwall/lkrg](https://github.com/openwall/lkrg) |
| Exploit style guide | [google/security-research - kernelCTF](https://github.com/google/security-research/tree/master/security-research/kernelctf) |
| PaX attack paradigm framework | [pax.grsecurity.net](https://pax.grsecurity.net) |
| FUZE (kernel UAF AEG) | [syssec.kaist.ac.kr/pub/2018/fuze_sec18.pdf](https://syssec.kaist.ac.kr/pub/2018/fuze_sec18.pdf) |
| KOOBE (kernel exploit gen) | [chengyusong.me/publications/koobe_sec20.pdf](https://chengyusong.me/publications/koobe_sec20.pdf) |
| SLAKE (slab layout AEG) | [chengyusong.me/publications/slake_ccs21.pdf](https://chengyusong.me/publications/slake_ccs21.pdf) |
| AEG (CMU) | [cs.cmu.edu/~aavgerin/papers/aeg-ndss-2011.pdf](https://cs.cmu.edu/~aavgerin/papers/aeg-ndss-2011.pdf) |
| Gollum (LLM exploit gen) | [seanheelan.io](https://seanheelan.io) |
| angr (binary analysis) | [github.com/angr/angr](https://github.com/angr/angr) |
| Syzkaller | [github.com/google/syzkaller](https://github.com/google/syzkaller) |
| AEG research overview | `docs/aeg-research.md` |
| All external refs in one place | This file (`docs/vkb.md`) |
