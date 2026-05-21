#ifndef SIDEWINDER_H
#define SIDEWINDER_H

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/mman.h>
#include <x86intrin.h>

#define CACHE_LINE_SIZE         64
#define PAGE_SIZE               4096
#define HUGE_PAGE_SIZE          0x200000  /* 2MB */
#define GIGA_PAGE_SIZE          0x40000000 /* 1GB */

#define MAX_CACHE_SETS          16384
#define DEFAULT_STRIDE          CACHE_LINE_SIZE
#define NUM_PROBES              10

/* Hammer test modes */
#define HAMMER_CLASSIC          0
#define HAMMER_FREQUENCY        1
#define HAMMER_MANY_SIDED       2

typedef struct {
    uint64_t hit_threshold;
    uint64_t miss_threshold;
    int      calibrated;
} cache_config_t;

typedef struct {
    int level;
    int size_kb;
    int ways;
    int sets;
    int line_size;
    int shared_by;
} cache_info_t;

typedef struct {
    cache_info_t l1d;
    cache_info_t l1i;
    cache_info_t l2;
    cache_info_t l3;
} cpu_cache_t;

typedef struct {
    int      total_pages;
    int      free_pages;
    int      page_size;
} hugepage_info_t;

typedef struct {
    uint64_t   base;
    uint8_t    *mapping;
    size_t     size;
    int        fd;
} mem_region_t;

typedef struct {
    uint64_t  phys_addr;
    uint64_t  virt_addr;
    uint64_t  row_index;
    uint64_t  bank;
    uint64_t  column;
    uint64_t  rank;
} dram_addr_t;

typedef struct {
    uint64_t addr;
    uint64_t bit_pos;
    uint8_t  from_val;
    uint8_t  to_val;
} flip_record_t;

#define MAX_FLIPS 4096
typedef struct {
    int            num_flips;
    flip_record_t  flips[MAX_FLIPS];
    uint64_t       total_activations;
    double         duration_sec;
} hammer_result_t;

typedef struct {
    double frequency;
    double phase;
    double amplitude;
    int    pattern_id;
} freq_pattern_t;

#define MAX_PATTERNS 64
typedef struct {
    int             num_patterns;
    freq_pattern_t  patterns[MAX_PATTERNS];
} freq_pattern_set_t;

#define SIDEWINDER_EXPORT __attribute__((visibility("default")))

/* cache.c */
SIDEWINDER_EXPORT void     sw_flush_line(const void *addr);
SIDEWINDER_EXPORT void     sw_flush_range(const void *start, size_t len);
SIDEWINDER_EXPORT void     sw_mfence(void);
SIDEWINDER_EXPORT void     sw_lfence(void);
SIDEWINDER_EXPORT uint64_t sw_reload_line(const void *addr);
SIDEWINDER_EXPORT int      sw_probe_set(uint8_t *buffer, int set_idx, int stride, int ways);
SIDEWINDER_EXPORT void     sw_prime_set(uint8_t *buffer, int set_idx, int stride, int ways);
SIDEWINDER_EXPORT void     sw_evict_set(uint8_t *buffer, int set_idx, int stride, int ways);
SIDEWINDER_EXPORT uint64_t sw_cache_calibrate(void *addr, int trials);
SIDEWINDER_EXPORT uint64_t sw_flush_reload(void *addr, uint64_t threshold);
SIDEWINDER_EXPORT void     sw_evict_buffer(void *addr, size_t size);

/* timer.c */
SIDEWINDER_EXPORT uint64_t sw_rdtsc(void);
SIDEWINDER_EXPORT uint64_t sw_rdtscp(void);
SIDEWINDER_EXPORT uint64_t sw_rdtsc_begin(void);
SIDEWINDER_EXPORT uint64_t sw_rdtsc_end(void);
SIDEWINDER_EXPORT uint64_t sw_timer_calibrate(void);

/* memory.c */
SIDEWINDER_EXPORT int      sw_alloc_huge_pages(int num_pages);
SIDEWINDER_EXPORT uint8_t *sw_map_huge_region(size_t size_mb);
SIDEWINDER_EXPORT void     sw_free_huge_region(uint8_t *addr, size_t size);
SIDEWINDER_EXPORT uint64_t sw_virt_to_phys(const void *vaddr);
SIDEWINDER_EXPORT int      sw_get_cache_info(cpu_cache_t *info);
SIDEWINDER_EXPORT int      sw_get_hugepage_info(hugepage_info_t *info);
SIDEWINDER_EXPORT void     sw_pin_to_core(int core);

/* hammer.c */
SIDEWINDER_EXPORT void     sw_hammer_classic(uint8_t *aggressor_a, uint8_t *aggressor_b,
                                             int iterations);
SIDEWINDER_EXPORT void     sw_hammer_frequency(uint8_t *buffer, uint64_t *row_addrs,
                                               int num_rows, freq_pattern_set_t *patterns,
                                               int total_activations);
SIDEWINDER_EXPORT void     sw_hammer_many_sided(uint8_t *buffer, uint64_t *aggressor_addrs,
                                                int num_aggressors, uint64_t victim_row,
                                                int activations_per);
SIDEWINDER_EXPORT int      sw_check_flips(uint8_t *buffer, size_t size,
                                          hammer_result_t *result);
SIDEWINDER_EXPORT double   sw_refresh_interval_measure(void);
SIDEWINDER_EXPORT void     sw_generate_freq_patterns(freq_pattern_set_t *ps, int count);

/* exploit_verify.c — Spy attack, targeted PTE flip, modprobe_path overwrite */

SIDEWINDER_EXPORT int      sw_spy_run_attack(uint8_t *output, int output_size, int threshold);
SIDEWINDER_EXPORT int      sw_find_ptes_in_spray(uint8_t *buffer, size_t buf_size,
                                                  uint64_t *found_addrs, int max_find,
                                                  int *num_found);
SIDEWINDER_EXPORT int      sw_targeted_pte_flip(uint64_t pte_virt_addr,
                                                 uint64_t *aggressor_rows, int num_aggressors,
                                                 uint8_t *hammer_buffer,
                                                 freq_pattern_set_t *patterns,
                                                 int activations_per_burst, int max_bursts);
SIDEWINDER_EXPORT int      sw_overwrite_kernel_page(uint64_t kernel_virt_addr,
                                                     const char *new_data, size_t data_len);
SIDEWINDER_EXPORT int      sw_trigger_modprobe_exec(void);

/* tsa_probe.c - TSA, GhostRace, BHI, prefetch KASLR, PTE escalation */
SIDEWINDER_EXPORT int      sw_tsa_probe_sq(uint8_t *probe_buffer, int threshold,
                                            int trials, int *leak_count);
SIDEWINDER_EXPORT int      sw_ghostrace_probe(uint8_t *probe_buffer, int threshold,
                                               int trials, int *speculative_hits);
SIDEWINDER_EXPORT int      sw_bhi_probe(uint8_t *probe_buffer, int threshold,
                                         int trials, int *retrain_hits);
SIDEWINDER_EXPORT uint64_t sw_prefetch_kaslr_probe(uint64_t kernel_candidate,
                                                    int measurements);
SIDEWINDER_EXPORT int      sw_pte_spray(uint8_t *buffer, size_t buffer_size,
                                         uint64_t **pte_candidates, int *num_found);
SIDEWINDER_EXPORT int      sw_kernel_write_via_pte(uint64_t pte_virt_addr,
                                                    uint64_t target_kernel_virt,
                                                    const char *new_data, size_t len);
SIDEWINDER_EXPORT int      sw_ssb_probe(uint8_t *probe_buffer, int threshold,
                                        int trials, int *speculative_hits);
SIDEWINDER_EXPORT int      sw_itlb_multihit_probe(int trials, int *page_faults);
SIDEWINDER_EXPORT int      sw_spectre_v1_probe(uint8_t *probe_buffer, int threshold,
                                               int trials, int secret_byte, int *speculative_hits);

/* VM-to-Host attack probes */
SIDEWINDER_EXPORT int      sw_vmscape_probe(uint8_t *probe_buffer, int threshold,
                                             int trials, int *leak_indicators);
SIDEWINDER_EXPORT int      sw_vmscape_exfiltrate(uint8_t *probe_buffer, int probe_size,
                                                   uint8_t *output, int output_size,
                                                   int threshold, int trials);
SIDEWINDER_EXPORT int      sw_l1tf_probe(uint8_t *probe_buffer, int threshold,
                                           int trials, int *leak_bytes);
SIDEWINDER_EXPORT int      sw_mds_probe(uint8_t *probe_buffer, int threshold,
                                          int trials, int *leaked_bytes);

/* Hertzbleed - DVFS timing side-channel */
SIDEWINDER_EXPORT int      sw_hertzbleed_probe(int iterations, int *timing_leaks);
SIDEWINDER_EXPORT int      sw_hertzbleed_calibrate_threshold(void);

/* ZenHammer - AMD Zen DDR5 Rowhammer */
SIDEWINDER_EXPORT void     sw_zenhammer_hammer(uint8_t *buffer, uint64_t *row_addrs,
                                               int num_rows, int aggressors_per_set,
                                               int total_activations, int amd_family);

#endif /* SIDEWINDER_H */
