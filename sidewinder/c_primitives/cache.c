#include "sidewinder.h"

void sw_flush_line(const void *addr) {
    _mm_clflush(addr);
    _mm_mfence();
}

void sw_flush_range(const void *start, size_t len) {
    const uint8_t *p = (const uint8_t *)start;
    const uint8_t *end = p + len;
    while (p < end) {
        _mm_clflush(p);
        p += CACHE_LINE_SIZE;
    }
    _mm_mfence();
}

void sw_mfence(void) {
    _mm_mfence();
}

void sw_lfence(void) {
    _mm_lfence();
}

uint64_t sw_reload_line(const void *addr) {
    volatile uint8_t *p = (volatile uint8_t *)addr;
    uint64_t start, end;

    _mm_mfence();
    start = __rdtsc();
    _mm_lfence();
    (void)*p;
    _mm_lfence();
    end = __rdtsc();
    _mm_mfence();

    return end - start;
}

int sw_probe_set(uint8_t *buffer, int set_idx, int stride, int ways) {
    uint64_t total = 0;
    int hits = 0;

    for (int w = 0; w < ways; w++) {
        uint8_t *p = buffer + (set_idx * ways * stride) + (w * stride);
        uint64_t t = sw_reload_line(p);
        if (t < 200)
            hits++;
        total += t;
    }

    return hits;
}

void sw_prime_set(uint8_t *buffer, int set_idx, int stride, int ways) {
    for (int w = 0; w < ways; w++) {
        volatile uint8_t *p = (volatile uint8_t *)(buffer + (set_idx * ways * stride) + (w * stride));
        (void)*p;
    }
    _mm_mfence();
}

void sw_evict_set(uint8_t *buffer, int set_idx, int stride, int ways) {
    for (int w = 0; w < ways; w++) {
        uint8_t *p = buffer + (set_idx * ways * stride) + (w * stride);
        _mm_clflush(p);
    }
    _mm_mfence();
}

uint64_t sw_cache_calibrate(void *addr, int trials) {
    uint64_t hit_total = 0, miss_total = 0;
    int hit_count = 0, miss_count = 0;
    volatile uint8_t *p = (volatile uint8_t *)addr;

    for (int i = 0; i < trials; i++) {
        /* Hit measurement */
        _mm_mfence();
        (void)*p;
        _mm_mfence();
        uint64_t start = __rdtsc();
        _mm_lfence();
        (void)*p;
        _mm_lfence();
        uint64_t end = __rdtsc();
        hit_total += (end - start);
        hit_count++;

        /* Miss measurement */
        _mm_clflush((void *)p);
        _mm_mfence();
        start = __rdtsc();
        _mm_lfence();
        (void)*p;
        _mm_lfence();
        end = __rdtsc();
        miss_total += (end - start);
        miss_count++;
    }

    uint64_t hit_avg_val  = hit_total / hit_count;
    uint64_t miss_avg_val = miss_total / miss_count;

    /* Threshold = midpoint between hit and miss averages */
    return (hit_avg_val + miss_avg_val) / 2;
}

uint64_t sw_flush_reload(void *addr, uint64_t threshold) {
    volatile uint8_t *p = (volatile uint8_t *)addr;

    (void)threshold;
    _mm_clflush((void *)p);
    _mm_mfence();
    uint64_t t = __rdtsc();
    _mm_lfence();
    (void)*p;
    _mm_lfence();
    uint64_t end = __rdtsc();

    return end - t;
}

void sw_evict_buffer(void *addr, size_t size) {
    uint8_t *p = (uint8_t *)addr;
    uint8_t *end = p + size;

    while (p < end) {
        _mm_clflush(p);
        p += CACHE_LINE_SIZE;
    }
    _mm_mfence();
}
