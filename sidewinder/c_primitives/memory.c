#include "sidewinder.h"

int sw_alloc_huge_pages(int num_pages) {
    const char *sys_path = "/proc/sys/vm/nr_hugepages";
    char buf[32];
    int fd, n;
    int old_val = 0;

    fd = open(sys_path, O_RDONLY);
    if (fd >= 0) {
        n = read(fd, buf, sizeof(buf) - 1);
        if (n > 0) {
            buf[n] = '\0';
            old_val = atoi(buf);
        }
        close(fd);
    }

    fd = open(sys_path, O_WRONLY);
    if (fd < 0) {
        if (errno == EACCES) return -2; /* need root */
        return -1;
    }

    snprintf(buf, sizeof(buf), "%d\n", num_pages);
    n = write(fd, buf, strlen(buf));
    close(fd);

    return (n > 0) ? old_val : -1;
}

uint8_t *sw_map_huge_region(size_t size_mb) {
    size_t size = size_mb * 1024 * 1024;
    int num_pages = (int)((size + HUGE_PAGE_SIZE - 1) / HUGE_PAGE_SIZE);

    sw_alloc_huge_pages(num_pages);

    uint8_t *addr = mmap(NULL, size,
                         PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB,
                         -1, 0);

    if (addr == MAP_FAILED) {
        addr = mmap(NULL, size,
                    PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE,
                    -1, 0);
        if (addr == MAP_FAILED)
            return NULL;

        madvise(addr, size, MADV_HUGEPAGE);
    }

    for (size_t i = 0; i < size; i += PAGE_SIZE) {
        volatile uint8_t *p = (volatile uint8_t *)(addr + i);
        (void)*p;
    }

    memset(addr, 0x41, size);
    _mm_mfence();

    return addr;
}

void sw_free_huge_region(uint8_t *addr, size_t size) {
    if (addr)
        munmap(addr, size);
}

uint64_t sw_virt_to_phys(const void *vaddr) {
    int fd;
    uint64_t page, entry;
    off_t off;

    fd = open("/proc/self/pagemap", O_RDONLY);
    if (fd < 0) return 0;

    page = (uint64_t)vaddr / PAGE_SIZE;
    off = page * sizeof(uint64_t);

    if (lseek(fd, off, SEEK_SET) != off) {
        close(fd);
        return 0;
    }

    if (read(fd, &entry, sizeof(uint64_t)) != sizeof(uint64_t)) {
        close(fd);
        return 0;
    }
    close(fd);

    if (!(entry & (1ULL << 63))) return 0;

    uint64_t pfn = entry & ((1ULL << 55) - 1);
    uint64_t phys = (pfn * PAGE_SIZE) + ((uint64_t)vaddr & (PAGE_SIZE - 1));

    return phys;
}

static void _sw_cpuid_count(unsigned int leaf, unsigned int subleaf,
                              unsigned int *eax, unsigned int *ebx,
                              unsigned int *ecx, unsigned int *edx) {
    __asm__ volatile("cpuid"
                     : "=a"(*eax), "=b"(*ebx), "=c"(*ecx), "=d"(*edx)
                     : "a"(leaf), "c"(subleaf));
}

int sw_get_cache_info(cpu_cache_t *info) {
    unsigned int eax, ebx, ecx, edx;

    memset(info, 0, sizeof(cpu_cache_t));

    for (int i = 0; ; i++) {
        _sw_cpuid_count(4, i, &eax, &ebx, &ecx, &edx);
        int type = eax & 0x1f;
        if (type == 0) break;

        int level = (eax >> 5) & 0x7;
        int ways = ((ebx >> 22) & 0x3ff) + 1;
        int partitions = ((ebx >> 12) & 0x3ff) + 1;
        int line_size = (ebx & 0xfff) + 1;
        int sets = ecx + 1;
        int size_kb = (ways * partitions * line_size * sets) / 1024;
        int threads = ((eax >> 14) & 0xfff) + 1;

        cache_info_t *ci = NULL;
        switch (level) {
            case 1:
                ci = (type == 1) ? &info->l1d : &info->l1i;
                break;
            case 2: ci = &info->l2; break;
            case 3: ci = &info->l3; break;
            default: continue;
        }

        ci->level = level;
        ci->size_kb = size_kb;
        ci->ways = ways;
        ci->sets = sets;
        ci->line_size = line_size;
        ci->shared_by = threads;
    }

    /* Fallback: read from sysfs */
    if (info->l1d.size_kb == 0) {
        FILE *f = fopen("/sys/devices/system/cpu/cpu0/cache/index0/size", "r");
        if (f) {
            char buf[16];
            int s = 0;
            if (fgets(buf, sizeof(buf), f)) {
                s = atoi(buf);
                if (buf[strlen(buf)-1] == 'K') ;
            }
            fclose(f);
            info->l1d.size_kb = s;
        }
    }
    if (info->l2.size_kb == 0) {
        FILE *f = fopen("/sys/devices/system/cpu/cpu0/cache/index1/size", "r");
        if (f) {
            char buf[16];
            int s = 0;
            if (fgets(buf, sizeof(buf), f)) s = atoi(buf);
            fclose(f);
            info->l2.size_kb = s;
        }
    }
    if (info->l3.size_kb == 0) {
        FILE *f = fopen("/sys/devices/system/cpu/cpu0/cache/index2/size", "r");
        if (f) {
            char buf[16];
            int s = 0;
            if (fgets(buf, sizeof(buf), f)) s = atoi(buf);
            fclose(f);
            info->l3.size_kb = s;
        }
    }

    return 0;
}

int sw_get_hugepage_info(hugepage_info_t *info) {
    int fd;
    char buf[64];
    int n;

    info->total_pages = 0;
    info->free_pages = 0;
    info->page_size = HUGE_PAGE_SIZE;

    fd = open("/proc/sys/vm/nr_hugepages", O_RDONLY);
    if (fd >= 0) {
        n = read(fd, buf, sizeof(buf) - 1);
        if (n > 0) { buf[n] = '\0'; info->total_pages = atoi(buf); }
        close(fd);
    }

    fd = open("/proc/sys/vm/nr_hugepages", O_RDONLY);
    if (fd >= 0) {
        /* free = total for now, kernel tracks separately via /proc/meminfo */
        close(fd);
    }

    FILE *f = fopen("/proc/meminfo", "r");
    if (f) {
        while (fgets(buf, sizeof(buf), f)) {
            if (strncmp(buf, "HugePages_Free:", 15) == 0)
                info->free_pages = atoi(buf + 15);
            if (strncmp(buf, "Hugepagesize:", 13) == 0)
                info->page_size = atoi(buf + 13) * 1024;
        }
        fclose(f);
    }

    if (info->free_pages < 0) info->free_pages = 0;
    return 0;
}
