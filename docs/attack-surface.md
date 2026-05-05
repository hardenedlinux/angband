# Linux Kernel Attack Surface & Exploit Vector Reference

A comprehensive catalog of kernel attack surfaces (subsystems, syscalls, and interfaces) and exploit vectors (bug classes, trigger mechanisms) relevant to automated exploit generation.

## Attack Surfaces by Subsystem

### Network Subsystem
| Interface | Privilege | Objects | Size Range |
|-----------|-----------|---------|------------|
| `socket()` | Unprivileged | socket, sock, proto_ops | kmalloc-256 to -4k |
| Netlink (`socket(AF_NETLINK)`) | Unprivileged | netlink_sock, nlmsghdr | kmalloc-256 to -2k |
| `setsockopt()`/`getsockopt()` | Unprivileged | Various option buffers | Variable |
| RTNETLINK (`rtnetlink`) | CAP_NET_ADMIN | macvlan_dev, veth, net_device | kmalloc-4k |
| Packet sockets (`AF_PACKET`) | Unprivileged | packet_sock, tpacket_req | kmalloc-512 to -4k |
| Nftables/Netfilter | Unprivileged | nft_table, nft_chain, nft_rule | kmalloc-256 to -2k |

### Filesystem Subsystem
| Interface | Privilege | Objects | Size Range |
|-----------|-----------|---------|------------|
| `open()`/`close()` | Unprivileged | file, inode, dentry | kmalloc-128 to -1k |
| `read()`/`write()` | Unprivileged | Various buffer structs | Variable |
| `mmap()` | Unprivileged | vm_area_struct | kmalloc-256 |
| `ioctl()` | Variable | Subsystem-specific | Variable |
| `setxattr()`/`getxattr()` | Unprivileged | xattr buffers | Variable (good spray) |
| Userfaultfd | May need CAP_SYS_PTRACE | uffd_msg, uffdio_register | kmalloc-256 |

### IPC Subsystem
| Interface | Privilege | Objects | Size Range |
|-----------|-----------|---------|------------|
| `msgget()`/`msgsnd()`/`msgrcv()` | Unprivileged | msg_msg, msg_queue | 48 to PAGE_SIZE |
| `shmget()`/`shmat()` | Unprivileged | shmid_kernel | kmalloc-256 |
| `semget()`/`semop()` | Unprivileged | sem_array | kmalloc-256 |
| `pipe()`/`pipe2()` | Unprivileged | pipe_inode_info, pipe_buffer | kmalloc-128 to -1k |

### Timer / Signal Subsystem
| Interface | Privilege | Objects | Size Range |
|-----------|-----------|---------|------------|
| `timerfd_create()`/`timerfd_settime()` | Unprivileged | timerfd_ctx (216 bytes) | kmalloc-256 |
| `timer_create()`/`timer_settime()` | Unprivileged | k_itimer | kmalloc-256 |
| `signalfd()` | Unprivileged | signalfd_ctx | kmalloc-256 |
| `eventfd()` | Unprivileged | eventfd_ctx | kmalloc-256 |

### Performance / Tracing Subsystem
| Interface | Privilege | Objects | Size Range |
|-----------|-----------|---------|------------|
| `perf_event_open()` | Need `perf_event_paranoid=-1` | perf_event, perf_buffer | kmalloc-256 to -4k |
| `bpf()` | May need `kernel.unprivileged_bpf_disabled=0` | bpf_prog, bpf_map | kmalloc-256 to -4k |

### Credential / Namespace Subsystem
| Interface | Privilege | Objects | Size Range |
|-----------|-----------|---------|------------|
| `clone()`/`unshare()` | Unprivileged | task_struct, cred, nsproxy | kmalloc-256 to -4k |
| `setuid()`/`setgid()` | Unprivileged | struct cred | kmalloc-192 |

### Memory Management
| Interface | Privilege | Objects | Size Range |
|-----------|-----------|---------|------------|
| `mmap()`/`munmap()` | Unprivileged | vm_area_struct | kmalloc-256 |
| `mprotect()` | Unprivileged | vm_area_struct modification | N/A |
| `madvise()` | Unprivileged | Page flags modification | N/A |
| `fallocate(FALLOC_FL_PUNCH_HOLE)` | Unprivileged (tmpfs) | Page cache manipulation | N/A |

### io_uring Subsystem
| Interface | Privilege | Objects | Size Range |
|-----------|-----------|---------|------------|
| `io_uring_setup()` | Unprivileged | io_ring_ctx | kmalloc-1k to -4k |
| `io_uring_enter()` | Unprivileged | io_kiocb, io_task_work | kmalloc-256 |
| `io_uring_register()` | Unprivileged | io_rsrc_node, io_mapped_ubuf | Variable |

## Exploit Vectors (Bug Classes)

### Memory Corruption

| Vector | Mechanism | Exploitability | Angband Priority |
|--------|-----------|----------------|-----------------|
| **Use-After-Free (UAF)** | Object freed while still referenced | ★★★★★ | P0 - 4 CVEs implemented |
| **Double-Free** | Object freed twice, corrupting freelist | ★★★★☆ | P0 |
| **Out-of-Bounds Write** | Write beyond object boundary | ★★★★☆ | P0 |
| **Out-of-Bounds Read** | Read beyond object boundary (infoleak) | ★★★☆☆ | P1 - leak stage |
| **Heap Overflow** | Write past allocated heap buffer | ★★★★☆ | P0 |
| **Stack Overflow** | Write past stack buffer | ★★★☆☆ | P2 |
| **Integer Overflow** | Arithmetic wrap leading to wrong size | ★★★☆☆ | P1 - grooming helper |

### Logic Bugs

| Vector | Mechanism | Exploitability | Angband Priority |
|--------|-----------|----------------|-----------------|
| **Race Condition** | Concurrent access with wrong sync | ★★★★☆ | P0 - timerfd is race-based |
| **Type Confusion** | Object misinterpreted as wrong type | ★★★☆☆ | P2 |
| **Reference Count Leak** | refcount never reaches 0 → never freed | ★★☆☆☆ | P3 |
| **Incomplete Cleanup** | Partial cleanup leaves stale state | ★★★☆☆ | P1 |
| **Out-of-Cancel** | workqueue cancel misuse | ★★★☆☆ | P1 (novel technique) |

### Attack Chains

| Vector | Steps | Example |
|--------|-------|---------|
| **UAF → msg_msg reclaim → func ptr hijack** | 3 steps | timerfd, perf, io_uring |
| **arbitrary free → cred_jar spray → uid=0** | 3 steps | DirtyCred pattern |
| **OOB write → pipe_buffer corrupt → page UAF → cred** | 4 steps | signalfd chain |
| **limited heap bug → SLUBStick → arbitrary r/w → escalate** | 4 steps | Cross-cache SLUBStick |

## Exploit Technique Catalog

### Groom (Heap Spray) Techniques

| # | Technique | Cache Target | Controllable Size | Privileged? | angband Use |
|---|-----------|-------------|-------------------|-------------|-------------|
| 1 | msg_msg spray | Any kmalloc | 48 → PAGE_SIZE | No | **ALL CVEs** |
| 2 | pipe_buffer spray | kmalloc-64 → 1k | 40 → 1024 | No | Template support |
| 3 | setxattr spray | Any kmalloc | User-controlled size | No | Not yet |
| 4 | keyctl spray | Any kmalloc | Key payload size | No | Not yet |
| 8 | cred_jar spray (DirtyCred) | cred_jar | Fixed (struct cred) | Need arbitrary free | Not yet |
| 9 | slab drain + buddy | N/A (page level) | 4KB pages | No | macvlan pattern drain |
| 10 | signalfd spray | kmalloc-256 | 104 (fixed) | No | Not yet |

### Leak (KASLR Bypass) Techniques

| # | Technique | Mechanism | Needs kptr_restrict=0? | angband Use |
|---|-----------|-----------|------------------------|-------------|
| 1 | /proc/kallsyms read | Direct symbolic resolution | Yes | CVE-2026-23209 (parent) |
| 2 | Side-channel timing | Probe syscall entry timing | No | All CVEs (fallback) |
| 3 | Prefetch KASLR | prefetch instruction timing | No | Not yet |
| 4 | KernelSnitch | Flush+reload on heap objects | No | Not yet |
| 5 | Residual data read | UAF object retains stale pointers | No | macvlan (residual in net_device) |
| 6 | msg_msg OOB read | Corrupt m_ts → read adjacent memory | No | Not yet |
| 7 | dmesg leak | Kernel log messages leak addresses | No | Debug-only |

### Primitive (Write/Read) Techniques

| # | Technique | Input | Output | CFI-Resistant? | angband Use |
|---|-----------|-------|--------|----------------|-------------|
| 1 | msg_msg reclaim + func ptr hijack | UAF in controlled object | Kernel code exec | No | timerfd, perf, io_uring |
| 2 | pcpu_stats corruption | Controlled pointer | Arbitrary kernel write | Yes | macvlan |
| 3 | dirty_pagetable | Page drain + PTE control | Arbitrary write | Yes | macvlan (full) |
| 4 | pipe_primitive | Pipe buffer ops corruption | Arbitrary r/w | Yes | Not yet |
| 5 | LL_ATK | List unlink on UAF | Code exec | Yes | Potential |
| 6 | wake_up_locked_poll | Fake wqh in reclaimed memory | Code exec (via func ptr) | No | timerfd |
| 7 | hrtimer hijack | Fake hrtimer.function | Code exec | No | timerfd (blocked by msg_msg offset) |
| 8 | SLUBStick | Timing channel → cross-cache | Arbitrary r/w | Yes | Not yet |
| 9 | signalfd cred overwrite | Page-UAF → signalfd → cred | Root | Yes (data-only) | Not yet |
| 10 | RBTree pointer copy | Double-insert → copy pointer | Pointer aliasing | Yes | Not yet |

### Escalate (Privilege Escalation) Techniques

| # | Technique | Type | Status in angband |
|---|-----------|------|-------------------|
| 1 | modprobe_path overwrite | Write → trigger | Implemented (placeholder for non-macvlan) |
| 2 | commit_creds ROP | Func ptr → ROP chain | Documented, needs gadgets |
| 3 | dirty_cred (cred overwrite) | Data-only corruption | Not yet |
| 4 | signalfd credential | Page-UAF → cred overwrite | Not yet |
| 5 | core_pattern overwrite | Write → crash → exec | Not yet |
| 6 | Kernel One Gadget | eBPF JIT gadget | Not yet |
| 7 | USMA (user-space mapping attack) | Map kernel pages to userspace | Not yet |

## Technique ↔ CVE Mapping

| CVE | Groom | Trigger | Leak | Primitive | Escalate |
|-----|-------|---------|------|-----------|----------|
| CVE-2026-23209 | msg_msg + slab drain | macvlan netlink | kallsyms + residual | pcpu_stats / dirty_pagetable | modprobe_path |

## Modern Mitigation ↔ Technique Resistance Matrix

| Technique | AUTOSLAB | RANDOM_KMALLOC | kCFI/IBT | VED msg | VED cred | CPU pinning |
|-----------|----------|---------------|----------|---------|----------|-------------|
| msg_msg reclaim | **Blocked** (same-type only) | Partial (pattern spray) | No effect | **Blocked** (different size) | No effect | 20-30% reduction |
| pcpu_stats corruption | No effect | No effect | **Yes** (data-only) | No effect | No effect | No effect |
| dirty_pagetable | **Blocked** | No effect | **Yes** (data-only) | No effect | No effect | No effect |
| commit_creds ROP | No effect | No effect | **Blocked** (ROP) | No effect | No effect | No effect |
| cred_jar spray | **Blocked** (cross-cache) | Partial | **Yes** (data-only) | No effect | **Blocked** (slab poison) | Partial |
| SLUBStick | **Blocked** (full mitigation) | Partial (reduced) | **Yes** (data-only) | No effect | No effect | Partial |
| Kernel One Gadget | No effect | No effect | **Bypasses** (JIT buffer) | No effect | No effect | No effect |

## Key References

| Source | URL | Topics |
|--------|-----|--------|
| PaX Future (2003) | pax.grsecurity.net/docs/pax-future.txt | Attack paradigms, CFI, ASLR design |
| VED 2026 DFI Security | hardenedvault.net/blog/2025-09-17-dfi-security/ | Data-only attacks, VED mitigations |
| msg_msg Recon & VED | hardenedvault.net/blog/2022-11-13-msg_msg-recon-mitigation-ved/ | msg_msg corruption patterns |
| SLUBStick Risk Assessment | hardenedvault.net/blog/2024-08-25-slubstick-risk-assessment-embedded-system/ | Cross-cache defense |
| AUTOSLAB | grsecurity.net/how_autoslab_changes_the_memory_unsafety_game | Type-based isolation |
| SLUBStick Paper | stefangast.eu/papers/slubstick.pdf | Timing side-channel attack |
| DirtyPipe | github.com/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits | Data-only escalation |
| pipe_primitive | github.com/veritas501/pipe-primitive | Pipe buffer corruption |
| Page UAF (Phrack #71) | phrack.org/issues/71/13 | Page-level UAF |
| kernelCTF exploits | google.github.io/security-research | 60+ winning exploit writeups |
| RANDOM_KMALLOC_CACHES | sam4k.com/exploring-linux-random-kmalloc-caches | v6.6 mitigation analysis |
