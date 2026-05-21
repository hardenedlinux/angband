#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "sidewinder.h"
#include <sched.h>

uint64_t sw_rdtsc(void) {
    return __rdtsc();
}

uint64_t sw_rdtscp(void) {
    unsigned int aux;
    return __rdtscp(&aux);
}

uint64_t sw_rdtsc_begin(void) {
    _mm_mfence();
    _mm_lfence();
    return __rdtsc();
}

uint64_t sw_rdtsc_end(void) {
    uint64_t t;
    _mm_lfence();
    unsigned int aux;
    t = __rdtscp(&aux);
    _mm_mfence();
    return t;
}

uint64_t sw_timer_calibrate(void) {
    uint64_t total = 0;
    int count = 512;

    for (int i = 0; i < count; i++) {
        uint64_t start = sw_rdtsc_begin();
        uint64_t end   = sw_rdtsc_end();
        total += (end - start);
    }

    return total / count;
}

void sw_pin_to_core(int core) {
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(core, &cpuset);
    sched_setaffinity(0, sizeof(cpu_set_t), &cpuset);
}
