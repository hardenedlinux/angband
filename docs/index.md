# Angband Knowledge Base — Index

This index maps the knowledge base to the framework's 7-stage exploit pipeline. Use this to find the right document for each stage of exploit development.

## Quick Start: Analyzing a New CVE

```
1. Identify attack surface   → docs/attack-surface.md
2. Classify bug type         → docs/bug-class-taxonomy.md
3. Determine groom method    → docs/heap-exploitation.md → Spray Selection Guide
4. Identify trigger path     → docs/bug-class-taxonomy.md → Bug Class Subtypes
5. Select leak method        → docs/attack-surface.md → Leak Techniques
6. Design primitive          → docs/novel-techniques.md + docs/attack-surface.md
7. Choose escalate method    → docs/attack-surface.md → Escalation Techniques
8. Implement via template    → templates/exploit_real.c.jinja2
```

## Knowledge Map by Pipeline Stage

```
STAGE 1: PREP
  └── Acquiring capabilities
      primitives/userns.c            — Namespace setup for CAP_NET_ADMIN
      primitives/kaslr.c             — Symbol resolution (kallsyms, sidechannel)
      docs/novel-techniques.md:10    — KernelSnitch (heap KASLR leak)

STAGE 2: GROOM
  └── Heap manipulation to prepare reclaim target
      docs/heap-exploitation.md
        ├── Spray Selection Guide (which spray for which target)
        ├── msg_msg Spray (kmalloc-256 to kmalloc-4k)
        ├── pipe_buffer Spray (kmalloc-64 to kmalloc-1k)
        ├── setxattr Spray (any kmalloc size)
        ├── Pattern Spray (PTE allocation verification)
        └── KernelSnitch (deterministic address leak)
      docs/novel-techniques.md:5    — CARDSHARK (alignment technique)
      docs/novel-techniques.md:8    — Cross-Cache Attacks

STAGE 3: TRIGGER
  └── Causing the bug condition
      docs/bug-class-taxonomy.md
        ├── UAF subtypes (hash stale, list stale, close-race)
        ├── OOB write triggers
        ├── Double-free triggers
        └── Race condition triggers
      docs/novel-techniques.md:9     — FALLOC_FL_PUNCH_HOLE (race window extension)
      docs/novel-techniques.md:11    — Out-of-Cancel (workqueue API misuse)
      CVE-specific docs (see below)

STAGE 4: LEAK
  └── KASLR bypass and symbol resolution
      primitives/kaslr.c             — kallsyms + sidechannel implementations
      docs/novel-techniques.md:10    — KernelSnitch (heap address leak)
      docs/novel-techniques.md:7     — Linear Mapping KASLR bypass (ARM64)
      docs/heap-exploitation.md      — msg_msg OOB read for residual data

STAGE 5: PRIMITIVE
  └── Converting bug into controlled write/read
      docs/novel-techniques.md
        ├── 1.  LL_ATK — Linked List Attack (no heap leak needed)
        ├── 2.  Kernel One Gadget — eBPF JIT gadget for CFI bypass
        ├── 3.  RBTree Pointer Copy — page-UAF via pointer aliasing
        ├── 4.  signalfd Credential — page-UAF → cred overwrite
        ├── 6.  ExpRace — Timer interrupt for race synchronization
        ├── 7.  CARDSHARK — Alignment via controlled allocation
        ├── 8.  Cross-Cache — Buddy allocator reuse
        ├── 9.  FALLOC_FL_PUNCH_HOLE — Race window extension
        ├── 11. Out-of-Cancel — Workqueue API misuse pattern
        └── 12. CVE-2025-38617 — Physmap spray for SLAB_VIRTUAL bypass
      docs/heap-exploitation.md
        ├── Escalation Patterns A-D (modprobe_path, commit_creds, signalfd, dirty_pagetable)
        └── Pattern E: Page-Level UAF via struct file spray
      primitives/dirty_pagetable.c   — PTE corruption for arbitrary write

STAGE 6: ESCALATE
  └── Converting write primitive into privilege escalation
      docs/heap-exploitation.md
        ├── Pattern A: modprobe_path overwrite
        ├── Pattern B: commit_creds via ROP chain
        ├── Pattern C: signalfd credential overwrite
        └── Pattern D: dirty_pagetable (PTE write → privilege)
      primitives/dirty_cred.c        — dirty_cred escalation
      primitives/msg_msg.c           — msg_msg primitive

STAGE 7: CLEANUP
  └── Stabilizing kernel state post-exploitation
      Template handles cleanup for all CVE profiles (close fds, free spray objects)
```

## CVE-Specific Analysis Docs

| CVE | Bug Class | Status | Key Doc |
|-----|-----------|--------|---------|
| CVE-2026-23209 | UAF (hash stale) | **UAF reachable; namespace root only** | `docs/CVE-2026-23209-analysis.md` |
| CVE-2026-23112 | OOB write | **Remote DoS; kernel panic on production configs** | `docs/CVE-2026-23112-analysis.md` |

**Note**: CVE-2026-23209 achieves **user namespace root** (uid=0 inside namespace) via pcpu_stats increment, NOT host root. The pcpu_stats primitive is too weak for `modprobe_path` overwrite. Host root requires function pointer hijack + ROP chain (not yet implemented). See the analysis doc for detailed feasibility assessment.

**Demo (vuln_drill)**: Works from uid=1000 directly via `/proc/vuln_drill` interface - true privilege escalation demo.

**Fake CVEs removed** (33289, 35555, 44269, 23412, 31431) - were hypothetical placeholders, not real vulnerabilities.

Each CVE doc follows this structure:
```
1. Status: WORKS / HARD / NOT EXPLOITABLE
2. Vulnerability: bug class, subsystem, capabilities, kernel config
3. Root Cause Flow: annotated code showing the bug trigger
4. Exploitation Chain: 7-stage breakdown with exact technique per stage
5. Struct Layout: verified offsets from pahole (or "unknown" if not verified)
6. Why It Works / Why It's Blocked: comparison with other CVEs
7. Potential Improvements: next steps for research
```

## Reference Docs

| Doc | Purpose | Key Sections |
|-----|---------|-------------|
| `attack-surface.md` | Subsystem enumeration, exploit vectors, technique catalog | 12 subsystems, 8 bug classes, 10 spray methods, 7 leak methods, 10 primitives, 7 escalation paths |
| `aeg-research.md` | AEG research survey mapped to angband pipeline | 10 AEG systems, technique→stage mapping, implementation roadmap |
| `bug-class-taxonomy.md` | Classify bug type → select approach | 11 bug classes, PaX attack paradigms, SLUBStick, technique selection matrix |
| `heap-exploitation.md` | SLUB internals, spray methods, escalation | SLUB layout, 6 spray methods, 5 escalation patterns, naive vs SLUBStick cross-cache |
| `novel-techniques.md` | Cutting-edge techniques from kernelCTF | 13 techniques with code examples, selection matrix |
| `mitigations-defense.md` | VED/LKRG/AUTOSLAB defense taxonomy | 5 defense categories, VED matrix, LKRG mechanisms |
| `manual_build.md` | QEMU guest testing walkthrough | VM setup, module loading, exploit execution |
| `KERNEL_MITIGATIONS.md` | Kernel addresses, struct offsets, CVE patch status | Verified symbols, timerfd_ctx layout, sysctl requirements |
| `ARCHITECTURE.md` | Framework internals | 7-stage pipeline, template structure, strategy map |
| `AGENTS.md` | Agent instructions | Environment setup, workflows, safety rules, exploit chaining |
| `TESTING.md` | End-to-end testing guide | Prerequisites, demo/CVE test steps, success criteria, troubleshooting |
| `vkb.md` | **Ring 0 reference index** | All external sources (papers, tools, CVEs) with title + URL |

## Technique Selection Quick Reference

```
What do I have?
  ├─ Function pointer accessible in freed object?
  │     → Go to: Func Ptr Hijack path
  │         docs/heap-exploitation.md: Pattern B (commit_creds ROP)
  │         docs/novel-techniques.md: 1, 2, 4 (LL_ATK, KOG, signalfd)
  │
  ├─ Only arbitrary kernel write?
  │     → Go to: Write Primitive path
  │         docs/heap-exploitation.md: Pattern A (modprobe_path)
  │
  ├─ Race condition window too small?
  │     → Go to: Race Window Extension
  │         docs/novel-techniques.md: 9 (FALLOC_FL_PUNCH_HOLE)
  │         docs/novel-techniques.md: 6 (ExpRace)
  │
  ├─ Limited heap bug (OOB read/write), need arbitrary r/w?
  │     → Go to: SLUBStick
  │         docs/novel-techniques.md: 13 (SLUBStick)
  │         docs/mitigations-defense.md: AUTOSLAB (only full mitigation)
  │
  └─ Need KASLR bypass + have heap address leak?
        → docs/novel-techniques.md: 10 (KernelSnitch)
```

## Adding a New CVE to the Framework

1. **Classify the bug** using `bug-class-taxonomy.md`
2. **Find similar CVE** in CVE-specific docs and use as reference
3. **Run pahole** on target kernel to get struct offsets
4. **Fill in the CVE template** (see CVE analysis format above)
5. **Select techniques** from heap-exploitation.md and novel-techniques.md
6. **Implement in template** via Jinja2 conditionals in `exploit_real.c.jinja2`
7. **Test in QEMU** via `run_and_verify.sh`
