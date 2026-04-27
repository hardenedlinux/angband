# vuln_drill

A CTF-style vulnerable kernel module for Angband exploit development,
modeled after [kernel-hack-drill](https://github.com/a13xp0p0v/kernel-hack-drill)
by Alexander Popov.

## Interface

| Proc file | Access | Purpose |
|-----------|--------|---------|
| `/proc/vuln_drill_act` | write-only | Send exploit actions |
| `/proc/vuln_drill` | read/write | Stage tracking for Angband pipeline |

## Actions

Write to `/proc/vuln_drill_act` with: `"ACT ITEM [VAL OFFSET]"`

| ACT | Name | Description |
|-----|------|-------------|
| 1 | ALLOC | Allocate item N (95 bytes, kmalloc-96) |
| 2 | CALLBACK | Invoke `item->callback()` |
| 3 | WRITE | Write `val` at `item->data[offset]` |
| 4 | FREE | `kfree(item)` **without** nulling the pointer |
| 5 | RESET | Set the item pointer to NULL |

## Vulnerabilities

These are **real** code bugs, not backdoors:

1. **Use-After-Free**: `DRILL_ACT_FREE` frees the item with `kfree()` but does
   not null the pointer in `items[]`. Subsequent `CALLBACK`, `WRITE`, or any
   access via the same item index operates on freed memory.

2. **UAF Callback Hijack**: `DRILL_ACT_CALLBACK` calls `item->callback()` without
   checking if the item has been freed. If the freed slot is reclaimed with
   attacker-controlled data, the callback pointer is hijacked.

3. **Out-of-Bounds Write**: `DRILL_ACT_WRITE` writes a value at an arbitrary
   offset within `item->data[]` without bounds checking.

## Exploit Techniques

### Basic: ret2usr (requires SMEP/SMAP/KASLR disabled)

```
Boot QEMU with: -cpu qemu64,-smep,-smap
Kernel cmdline:  nokaslr pti=off
```

1. `ALLOC item 3` -- allocate in kmalloc-96
2. `FREE item 3` -- UAF: pointer not nulled
3. `setxattr()` spray -- reclaim freed slot with fake `drill_item_t`
   containing `callback = root_it`
4. `CALLBACK item 3` -- calls `root_it()` which does
   `commit_creds(prepare_kernel_cred(init_task))`
5. uid=0, spawn shell

### Advanced techniques (not yet automated by Angband)

- **ROP + SMEP bypass**: See `kernel-hack-drill/drill_uaf_callback_rop_smep.c`
- **ROP + SMAP bypass**: See `kernel-hack-drill/drill_uaf_callback_rop_smap.c`
- **Dirty Pipe via pipe_buffer**: See `kernel-hack-drill/drill_uaf_w_pipe_buffer.c`
- **Dirty Pagetable via PTE**: See `kernel-hack-drill/drill_uaf_w_pte.c`
- **msg_msg OOB read**: See `kernel-hack-drill/drill_uaf_w_msg_msg.c`

## Build

```bash
# Inside the QEMU guest:
cd /mnt/angband/module/vuln_drill
make
sudo insmod vuln_drill.ko
```

## Safety

This module contains **real vulnerabilities** that can be exploited for
privilege escalation. **Only use inside an isolated QEMU guest.**
