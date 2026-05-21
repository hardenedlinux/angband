/* hertzbleed.c - DVFS timing side-channel probe (CVE-2022-23823, CVE-2022-24436)
 *
 * Hertzbleed exploits CPU Dynamic Voltage and Frequency Scaling (DVFS).
 * On modern CPUs, the processor adjusts its frequency based on power draw.
 * Certain data-dependent operations draw more power, causing the CPU to
 * throttle down. This frequency change is observable via timing.
 *
 * Affected: Intel 10th-12th gen, AMD Zen 2/3/4 (with DVFS enabled)
 */

#include "sidewinder.h"

/* Heavy 64-bit multiply-add chain - power depends on operand bit patterns.
 * Multipliers with many 1 bits cause more switching activity.
 */
static uint64_t power_workload(uint64_t seed, int iterations) {
    uint64_t result = seed;
    volatile uint64_t sink = 0;
    for (int i = 0; i < iterations; i++) {
        result = result * 0x9E3779B97F4A7C15ULL + (uint64_t)i;
        result ^= (result >> 33);
        sink += result;
    }
    return sink;
}

/* Measure time to execute workload with different data patterns */
SIDEWINDER_EXPORT int sw_hertzbleed_probe(int iterations, int *timing_leaks) {
    int leaks = 0;
    int samples = iterations > 0 ? iterations : 1000;
    int workload_iter = 100000;

    /* Pattern A: All zeros - minimal switching, low power */
    uint64_t times_zero[100];
    int idx = 0;
    for (int s = 0; s < samples && idx < 100; s += (samples / 100)) {
        uint64_t t0 = sw_rdtsc_begin();
        volatile uint64_t r = power_workload(0, workload_iter);
        uint64_t t1 = sw_rdtsc_end();
        times_zero[idx++] = t1 - t0;
        (void)r;
    }

    /* Pattern B: All ones - high switching, high power */
    uint64_t times_ones[100];
    idx = 0;
    for (int s = 0; s < samples && idx < 100; s += (samples / 100)) {
        uint64_t t0 = sw_rdtsc_begin();
        volatile uint64_t r = power_workload(0xFFFFFFFFFFFFFFFFULL, workload_iter);
        uint64_t t1 = sw_rdtsc_end();
        times_ones[idx++] = t1 - t0;
        (void)r;
    }

    /* Pattern C: Alternating bits - maximum switching */
    uint64_t times_alt[100];
    idx = 0;
    for (int s = 0; s < samples && idx < 100; s += (samples / 100)) {
        uint64_t t0 = sw_rdtsc_begin();
        volatile uint64_t r = power_workload(0x5555555555555555ULL, workload_iter);
        uint64_t t1 = sw_rdtsc_end();
        times_alt[idx++] = t1 - t0;
        (void)r;
    }

    /* Pattern D: Random-ish pattern */
    uint64_t times_rand[100];
    idx = 0;
    for (int s = 0; s < samples && idx < 100; s += (samples / 100)) {
        uint64_t t0 = sw_rdtsc_begin();
        volatile uint64_t r = power_workload(0xDEADBEEFCAFEBABEULL, workload_iter);
        uint64_t t1 = sw_rdtsc_end();
        times_rand[idx++] = t1 - t0;
        (void)r;
    }

    /* Compute averages */
    uint64_t avg_zero = 0, avg_ones = 0, avg_alt = 0, avg_rand = 0;
    for (int i = 0; i < 100; i++) {
        avg_zero += times_zero[i];
        avg_ones += times_ones[i];
        avg_alt  += times_alt[i];
        avg_rand += times_rand[i];
    }
    avg_zero /= 100;
    avg_ones /= 100;
    avg_alt  /= 100;
    avg_rand /= 100;

    /* Find min/max across patterns */
    uint64_t min_t = avg_zero;
    uint64_t max_t = avg_zero;
    if (avg_ones < min_t) min_t = avg_ones;
    if (avg_alt  < min_t) min_t = avg_alt;
    if (avg_rand < min_t) min_t = avg_rand;
    if (avg_ones > max_t) max_t = avg_ones;
    if (avg_alt  > max_t) max_t = avg_alt;
    if (avg_rand > max_t) max_t = avg_rand;

    uint64_t delta = max_t - min_t;

    /* Threshold: ~500 cycles difference indicates DVFS leakage */
    uint64_t threshold = 500;

    if (delta > threshold) {
        leaks = (int)(delta / 10);
    }

    if (timing_leaks) *timing_leaks = leaks;
    return leaks > 0 ? 1 : 0;
}

SIDEWINDER_EXPORT int sw_hertzbleed_calibrate_threshold(void) {
    int leaks;
    return sw_hertzbleed_probe(100, &leaks);
}
