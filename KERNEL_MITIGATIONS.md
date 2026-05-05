# Kernel Exploit Status

## Verified Kernel Addresses (6.8.0-106-generic)

| Symbol | Address |
|--------|---------|
| commit_creds | `0xffffffff8e7472f0` |
| prepare_kernel_cred | `0xffffffff8e747870` |
| modprobe_path | `0xffffffff90dde440` |
| init_task | `0xffffffff90c0fd40` |

## Verified Struct Offsets (pahole)

### timerfd_ctx (216 bytes)
```
union t        @ 0 (hrtimer=64, alarm=120)
tintv          @ 120
moffs          @ 128
wqh            @ 136 (lock@136+4b hole+head@144)
ticks          @ 160
clockid        @ 168
expired        @ 172
rcu            @ 176
clist          @ 192
cancel_lock    @ 208
might_cancel   @ 212
```

### msg_msg → timerfd_ctx reclaim mapping
```
mtext[0]   = hrtimer.base
mtext[72]  = tintv
mtext[80]  = moffs
mtext[88]  = wqh.lock
mtext[96]  = wqh.head
mtext[112] = ticks
mtext[124] = expired
```

### wait_queue_entry (40 bytes)
```
flags    @ 0
private  @ 8
func     @ 16  ← HIJACK TARGET (function pointer)
entry    @ 24
```

## CVE Status (Ubuntu 6.8.0-111)

| CVE | Subsystem | Escalation | Status |
|-----|-----------|-----------|--------|
| CVE-2026-23209 | macvlan | modprobe_path | PATCHED (works on -106) |

## Escalation Paths

### A: modprobe_path (write-based)
1. UAF gives write to kernel address
2. Overwrite modprobe_path with payload path
3. Execute invalid ELF → kernel calls payload as root

### B: commit_creds (code execution)
1. UAF gives function pointer hijack → `func(rdi=our_data)`
2. Set func to stack pivot gadget (`push rdi; pop rsp; ret`)
3. ROP chain in reclaimed memory: `commit_creds(prepare_kernel_cred(0))`
4. Immediate root (no file operations needed)

## Complete Exploit Flow (timerfd example)

```
Groom:   Create timerfds (CLOCK_REALTIME + CANCEL_ON_SET) + dup + msg_msg init
Trigger: Close primary → kfree_rcu → rearm via dup → close dup
         (timerfd_setup_cancel re-adds ctx to cancel_list)
Primitive: Wait RCU → spray msg_msg with fake wqh (mtext[88]=0, mtext[96]=kheap_ptr)
           settimeofday → clock_was_set → wake_up_locked_poll → func() call
Escalate: func points to ROP chain → commit_creds → root
```

## Missing for Full Exploitation

1. **ROP gadget addresses** - need decompressed kernel (zstd) + ROPgadget scan
2. **kheap address** for fake waitqueue entry pointer
3. **UAF trigger implementation** for perf and io_uring

## Mitigations Required

```bash
sudo sysctl -w kernel.perf_event_paranoid=-1
sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0
sudo sysctl -w kernel.kptr_restrict=0
```
