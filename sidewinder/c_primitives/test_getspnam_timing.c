#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <x86intrin.h>
#include <pwd.h>
#include <errno.h>

/* Test: Does calling getspnam("root") from non-root cause
 * cache timing changes that we can observe?
 *
 * Strategy:
 * 1. Flush a known cache line (libc text page)
 * 2. Call getspnam("root") - kernel will try to read /etc/shadow
 * 3. Probe our cache line
 *
 * If kernel's shadow read evicts our cache line → we see a miss
 * If kernel's shadow read doesn't affect our line → we see a hit
 */

static inline uint64_t reload_line(void *addr) {
    volatile uint8_t *p = addr;
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

static inline void flush_line(void *addr) {
    _mm_clflush(addr);
    _mm_mfence();
}

int main() {
    /* Use first page of libc as our probe */
    int fd = open("/lib/x86_64-linux-gnu/libc.so.6", O_RDONLY);
    if (fd < 0) fd = open("/lib64/libc.so.6", O_RDONLY);
    if (fd < 0) { perror("open libc"); return 1; }

    uint8_t *libc_map = mmap(NULL, 4096, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (libc_map == MAP_FAILED) { perror("mmap"); return 1; }

    /* Calibrate */
    uint64_t t_hit = reload_line(libc_map);
    flush_line(libc_map);
    _mm_mfence();
    uint64_t t_miss = reload_line(libc_map);
    uint64_t threshold = (t_hit + t_miss) / 2 + 20;

    printf("[*] Calibration: hit=%lu, miss=%lu, threshold=%lu\n",
           t_hit, t_miss, threshold);
    printf("[*] Testing getspnam() cache effects:\n\n");

    /* Test: flush -> getspnam -> probe */
    int hits_getspnam = 0;
    int hits_getpwnam = 0;

    for (int trial = 0; trial < 100; trial++) {
        flush_line(libc_map);
        _mm_mfence();

        /* Try getspnam("root") */
        struct passwd *pw = getspnam("root");
        (void)pw;

        uint64_t t = reload_line(libc_map);
        if (t < threshold) hits_getspnam++;
    }

    printf("    getspnam(\"root\"): %d / 100 hits\n", hits_getspnam);

    /* Comparison: getpwnam("root") - also reads passwd file */
    for (int trial = 0; trial < 100; trial++) {
        flush_line(libc_map);
        _mm_mfence();

        struct passwd *pw = getpwnam("root");
        (void)pw;

        uint64_t t = reload_line(libc_map);
        if (t < threshold) hits_getpwnam++;
    }

    printf("    getpwnam(\"root\"): %d / 100 hits\n", hits_getpwnam);

    /* Comparison: getpwnam("shawn") - current user */
    for (int trial = 0; trial < 100; trial++) {
        flush_line(libc_map);
        _mm_mfence();

        struct passwd *pw = getpwnam("shawn");
        (void)pw;

        uint64_t t = reload_line(libc_map);
    }

    printf("\n[*] Result:\n");
    if (hits_getspnam == hits_getpwnam) {
        printf("    Same hit rate for getspnam and getpwnam.\n");
        printf("    Kernel likely checks permissions before reading shadow.\n");
    } else {
        printf("    DIFFERENCE: getspnam=%d, getpwnam=%d\n", hits_getspnam, hits_getpwnam);
    }

    munmap(libc_map, 4096);
    return 0;
}
