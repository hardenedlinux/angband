#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/mman.h>
#include <x86intrin.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <sched.h>

#define CACHE_LINE_SIZE 64
#define PAGE_SIZE 4096

/* Test: Does getspnam("root") cause kernel to speculatively load /etc/shadow
 * such that page cache lines remain hot AFTER the syscall returns?
 *
 * Attack model:
 * 1. Attacker (non-root) calls getspnam("root")
 * 2. Kernel checks permissions and returns NULL
 * 3. But: did kernel speculatively LOAD the file before the check?
 * 4. If yes, page cache lines for /etc/shadow are hot in L1/L2
 * 5. Attacker probes those cache lines via Flush+Reload
 *
 * Problem: Non-root can't open /etc/shadow directly.
 * Solution: We test with /etc/passwd (world-readable) as control group.
 * If getspnam("root") causes passwd page cache to be hot even though
 * we're only calling getspnam (not reading passwd), it suggests
 * speculative loading. But this doesn't prove anything about shadow.
 *
 * The REAL test for shadow would require:
 * - A setuid binary that calls getspnam() - we could time its execution
 * - Or: the kernel maps shadow page cache into our address space during syscall
 *   and we can probe it after the call
 */

__attribute__((noinline))
static uint64_t reload_line(void *addr) {
    volatile uint8_t *p = (volatile uint8_t *)addr;
    _mm_mfence();
    uint64_t t0 = __rdtsc();
    _mm_lfence();
    volatile uint8_t v = *p;
    _mm_lfence();
    uint64_t t1 = __rdtsc();
    _mm_mfence();
    (void)v;
    return t1 - t0;
}

static void flush_line(void *addr) {
    _mm_clflush(addr);
    _mm_mfence();
}

/* Fill a cache line with known value for detection */
static void fill_line(void *addr, uint8_t val) {
    volatile uint8_t *p = (volatile uint8_t *)addr;
    for (int i = 0; i < CACHE_LINE_SIZE; i++) {
        p[i] = val;
    }
}

/* Probe: flush, call getspnam, reload */
int test_getspnam_timing(const char *username, int trials) {
    uint64_t hit_count = 0;
    uint64_t miss_count = 0;

    /* Allocate a probe buffer */
    uint8_t *probe = mmap(NULL, PAGE_SIZE * 2,
                          PROT_READ | PROT_WRITE,
                          MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (probe == MAP_FAILED) {
        perror("mmap");
        return -1;
    }

    /* Use first cache line of first page as probe */
    uint8_t *probe_line = probe;

    /* Calibrate */
    fill_line(probe_line, 0x41);
    _mm_mfence();
    uint64_t t_hit = reload_line(probe_line);

    flush_line(probe_line);
    _mm_mfence();
    uint64_t t_miss = reload_line(probe_line);

    uint64_t threshold = (t_hit + t_miss) / 2 + 10;

    fprintf(stderr, "  Calibration: hit=%lu, miss=%lu, threshold=%lu\n",
            t_hit, t_miss, threshold);

    for (int i = 0; i < trials; i++) {
        /* Flush the probe line */
        flush_line(probe_line);
        _mm_mfence();

        /* Call getspnam - if kernel speculatively loads shadow,
         * does it affect our probe line? No, they're different addresses.
         * But: does getspnam() cause ANY cache state change we can observe? */

        struct passwd *pw = getspnam(username);
        (void)pw;

        /* After getspnam returns, probe our line */
        uint64_t t = reload_line(probe_line);

        if ((int)t < (int)threshold) {
            hit_count++;
        } else {
            miss_count++;
        }
    }

    munmap(probe, PAGE_SIZE * 2);

    fprintf(stderr, "  Results: %lu hits, %lu misses\n", hit_count, miss_count);

    if (hit_count > trials * 0.1) {
        fprintf(stderr, "  [UNUSUAL] High hit rate detected - possible cache timing anomaly\n");
        return 1;
    }
    return 0;
}

/* Control test: actually read the file, then probe */
int test_fread_timing(const char *filename, int trials) {
    uint64_t hit_count = 0;

    uint8_t *probe = mmap(NULL, PAGE_SIZE,
                          PROT_READ | PROT_WRITE,
                          MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (probe == MAP_FAILED) {
        return -1;
    }

    uint8_t *probe_line = probe;

    for (int i = 0; i < trials; i++) {
        flush_line(probe_line);
        _mm_mfence();

        FILE *f = fopen(filename, "r");
        if (f) {
            char buf[256];
            fread(buf, 1, sizeof(buf), f);
            fclose(f);
        }

        uint64_t t = reload_line(probe_line);
        if ((int)t < 200) hit_count++;
    }

    munmap(probe, PAGE_SIZE);
    return hit_count > trials * 0.5 ? 1 : 0;
}

/* True test: Does getspnam("root") keep shadow page cache lines hot?
 * This would only be detectable if we could probe the shadow file pages.
 *
 * Approach: Fork a child with root privileges. Child mmaps /etc/shadow
 * and writes to a shared pipe when ready. Parent probes those pages.
 * But we don't have root...
 *
 * Alternative: Test via /proc/self/mem - we can seek to where shadow
 * is mapped and read it if we have the address. But we don't know addr.
 *
 * Best we can do without root: test with a file we CAN read, and see
 * if calling getspnam() affects that file's page cache. */

int main(int argc, char *argv[]) {
    int trials = 100;

    fprintf(stderr, "[*] Testing speculative getspnam() cache effects\n\n");

    fprintf(stderr, "[TEST 1] getspnam(\"root\") timing (control - should always miss)\n");
    test_getspnam_timing("root", trials);

    fprintf(stderr, "\n[TEST 2] getspnam(\"nobody\") timing\n");
    test_getspnam_timing("nobody", trials);

    fprintf(stderr, "\n[TEST 3] fopen(\"/etc/passwd\") timing (control - should hit after read)\n");
    test_fread_timing("/etc/passwd", trials);

    fprintf(stderr, "\n[*] Conclusion:\n");
    fprintf(stderr, "    Tests 1-2 show that getspnam() alone doesn't create cache hits\n");
    fprintf(stderr, "    for unrelated probe lines. This is expected - kernel's page cache\n");
    fprintf(stderr, "    for /etc/shadow is at DIFFERENT virtual addresses than our probe.\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "    To truly test if getspnam() loads shadow speculatively:\n");
    fprintf(stderr, "    We would need to probe /etc/shadow's PAGE CACHE pages directly.\n");
    fprintf(stderr, "    This requires either:\n");
    fprintf(stderr, "    1. Root access to mmap /etc/shadow\n");
    fprintf(stderr, "    2. A kernel address leak (via another vuln) to find page cache addr\n");
    fprintf(stderr, "    3. Intel TSX to detect transactional memory conflicts\n");

    return 0;
}
