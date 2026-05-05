# AEG (Automated Exploit Generation) Research & Angband Integration

A survey of open research in automated exploit generation, mapped to the angband kernel exploit framework. Focus on techniques that can improve angband's 7-stage pipeline.

## Key AEG Research Timeline

```
2011: AEG (CMU)         — First automated exploit generation for userspace
2016: Mayhem/CGC        — DARPA Cyber Grand Challenge winner
2018: FUZE              — First kernel UAF automated exploitation
2020: KOOBE             — Automated kernel exploit opportunity discovery  
2021: SLAKE             — Automated slab layout for kernel exploitation
2021: HEAPO             — Heap layout optimization
2022: Syzkaller+        — Bug finding → exploitation bridging
2023: Gollum            — LLM-guided exploit search
2024: AutoSlab/KAPO     — Kernel automatic primitive orchestration
```

## Foundational AEG Systems

### AEG: Automatic Exploit Generation (CMU, 2011)

**Paper**: Avgerinos et al., "AEG: Automatic Exploit Generation", NDSS 2011

**Core approach**:
```
Source/Binary → Symbolic Execution → Bug Finding → Exploit Generation
                                              ↓
                              [Exploitable condition found]
                                              ↓
                         Constraint solver: find input that triggers bug
                         AND hijacks control flow (EIP overwrite)
                                              ↓
                              [Generate exploit binary/script]
```

**Key contributions**:
- First end-to-end automated exploit generation
- Uses symbolic execution (KLEE-like) to find bugs and generate exploits
- Verifier-based approach: replay + verify exploitation succeeded
- Handles stack overflow, format string, and heap overflow bugs

**Relevance to angband**: The "bug finding → exploit generation" pipeline is the same structure angband uses but angband starts from known CVEs. AEG's constraint solver approach could help angband automate the "what offsets work?" problem for msg_msg sprays.

### Mayhem / DARPA Cyber Grand Challenge (2016)

**Project**: ForAllSecure Mayhem, won DARPA CGC 2016

**Core approach**:
```
Binary → Hybrid Execution (Concrete + Symbolic) → Vulnerability Detection
                                                          ↓
                                           [Exploitable Path Found]
                                                          ↓
                                   Patch Generation + Proof of Vulnerability
```

**Key contributions**:
- Hybrid concrete+symbolic execution for binary-only targets
- Fully automated: no human intervention during the competition
- Generates both exploits AND patches
- Proved that fully automated exploitation is viable at DARPA scale

**Relevance to angband**: Mayhem's hybrid execution approach is relevant for angband's "trigger" stage - given a CVE description, Mayhem-style symbolic execution could automatically find the triggering inputs. The patch generation capability is also interesting for angband's "cleanup" stage.

## Kernel-Specific AEG Systems

### FUZE: Kernel UAF Exploitation (USENIX Security 2018)

**Paper**: Wu et al., "FUZE: Towards Facilitating Exploit Generation for Kernel Use-After-Free Vulnerabilities", USENIX Security 2018

**Core approach**:
```
Kernel UAF Bug
      ↓
1. UAF Reachability Analysis — Can the freed object be accessed?
      ↓
2. Heap Manipulation Planning — Which spray technique? What size?
      ↓
3. Exploit Primitive Discovery — What can we achieve? (read/write/exec)
      ↓
4. Exploit Synthesis — Generate the exploit binary
```

**Key contributions**:
- **UAF Classification**: Classifies UAF into types (alloc-free-use, free-use, use-free)
- **Heap Feng Shui Automation**: Automatically determines spray size, count, and allocation pattern
- **Exploit Primitive Ranking**: Ranks exploitation primitives by reliability and capability
- Evaluated on 15 Linux kernel CVEs

**FUZE's UAF Classification**:
| Type | Pattern | angband CVE Example |
|------|---------|-------------------|
| Free-Use | Free → Use (alloc happened elsewhere) | CVE-2026-23209 (macvlan) |

**Relevance to angband (HIGH)**:
- FUZE's UAF classification directly maps to angband's CVE_Analyzer
- Heap manipulation planning → angband's "groom" stage
- Exploit primitive discovery → angband's "primitive" stage
- Could automate the spray parameter selection (currently manual in vuln_analyzer.py)

### KOOBE (USENIX Security 2020)

**Paper**: Chen et al., "KOOBE: Towards Facilitating Exploit Generation for the Linux Kernel", USENIX Security 2020

**Core approach**:
```
Kernel Binary + Bug Report
      ↓
1. Vulnerability Capability Analysis — What can the bug do?
      ↓
2. Exploitation Primitive Search — Find objects we can corrupt
      ↓
3. Interaction Graph Construction — Map reachable code paths
      ↓
4. Capability Amplification — Chain primitives for escalation
      ↓
5. Exploit Synthesis
```

**Key contributions**:
- **Interaction Graph**: Maps all kernel code paths reachable from the bug
- **Capability Amplification**: Automatic chaining (e.g., limited write → arbitrary free → cred spray)
- **Multi-path exploitation**: Tries multiple exploitation strategies in parallel
- Evaluated on 27 Linux kernel vulnerabilities

**Capability Amplification Chains** (from KOOBE):
```
Limited Write → msg_msg Spray → Arbitrary Read
Limited Write → msg_msg Spray → Arbitrary Free → cred_jar Spray → Root
OOB Read → KASLR Leak → msg_msg Spray → Arbitrary Write → modprobe_path
OOB Write → pipe_buffer Corruption → Arbitrary Read/Write
```

**Relevance to angband (HIGHEST)**:
- KOOBE's capability amplification is exactly what angband's "chaining" module implements
- The interaction graph could be used by angband to discover novel exploitation paths
- Multi-path parallel execution → angband could try modprobe_path AND commit_creds simultaneously

### SLAKE: Slab Layout for Kernel Exploitation (CCS 2021)

**Paper**: Chen et al., "SLAKE: Facilitating Slab Manipulation for Exploiting Vulnerabilities in the Linux Kernel", CCS 2021

**Core approach**:
```
Target Object (e.g., timerfd_ctx)
      ↓
1. Slab State Modeling — Where is the object in the slab?
      ↓
2. Allocation Sequence Planning — What alloc/free sequence places objects?
      ↓
3. Heap Layout Synthesis — Generate the spray program
      ↓
4. Layout Verification — Test in kernel + adjust
```

**Key contributions**:
- **Slab State Model**: Models the SLUB allocator's freelist, partial/full slabs, and per-CPU caches
- **Allocation Planning**: Automatically computes spray count, size, and interleaving
- **CARDSHARK-style alignment**: Automatically positions objects at desired offsets
- Verified against 10 real kernel CVEs

**Slab State Tracking**:
```
Slab Page: [obj0][obj1][FREE][obj3][FREE][obj5]
                     ↑                    ↑
              Next alloc here        Then here
              
SLAKE tracks: free list order, partial slab count, CPU cache state
              → determines exactly where next allocation lands
```

**Relevance to angband (HIGH)**:
- SLAKE could automate angband's spray parameter selection
- Eliminate blind pattern page scanning (currently 16-offset brute force in macvlan)
- Could generate the msg_msg spray parameters automatically from CVE config
- The slab state model would help predict where reclaimed objects land

### HEAPO: Heap Layout Optimization (2021)

**Paper**: Related to SLAKE, focuses on optimization of heap layout for exploitation reliability.

**Key insight**: The optimal spray layout is a constraint optimization problem:
```
Minimize: number of spray objects
Subject to:
  - Target object reclaimed at specified offset
  - Adjacent objects not corrupted by spray overflow
  - Slab cache not exhausted (avoid buddy allocator)
```

**Relevance to angband**: Could optimize spray parameters automatically instead of hard-coding `#define SPRAY_COUNT 256`.

## LLM-Assisted AEG

### Gollum (USENIX Security 2023)

**Paper**: Heelan et al., "Gollum: Modular and Greybox Exploit Generation for Heap Overflows in Interpreters", 2023

**Core approach**:
```
Bug Description (natural language / structured)
      ↓
1. LLM decomposes bug into exploitation stages
      ↓
2. For each stage: generate candidate exploit primitives
      ↓
3. Greybox testing: test each primitive, collect feedback
      ↓
4. LLM synthesizes full exploit from successful primitives
```

**Key contributions**:
- First use of LLMs for automated exploit generation
- Greybox approach: doesn't need source code
- Modular: each exploitation stage handled independently
- Generates working exploits for JavaScript engine bugs

**Relevance to angband (MEDIUM)**:
- Gollum's modular stage approach mirrors angband's 7-stage pipeline
- LLM-guided primitive selection → could replace manual technique selection
- Greybox feedback → angband already does this via QEMU testing

### LLM for Kernel Exploitation (2024+)

Emerging research:
- **ChatGPT-assisted exploit writing**: Researchers using LLMs to draft exploit code
- **VulnGPT/ExploitGPT**: Fine-tuned models for vulnerability analysis
- **Automated code review for patch analysis**: LLMs identify security fixes in commit diffs

**Relevance to angband**: 
- LLMs could help draft technique-specific C code for the Jinja2 template
- Patch diff analysis → auto-classify bug type (currently regex-based)
- Code generation for missing primitive implementations

## Bug Finding → Exploit Generation Bridge

### Syzkaller → Exploit Pipeline

**Syzkaller**: Google's kernel fuzzer (coverage-guided, finds ~1000 bugs/year)

**The gap**: Syzkaller produces crash reports, not exploits

**Bridging research**:
```
Syzkaller crash report
      ↓
[Automatic root cause analysis] — What object? What bug type?
      ↓
[Capability assessment] — Can this be exploited? (FUZE-style)
      ↓
[Exploit synthesis] — Generate exploit (KOOBE/slaKE-style)
      ↓
[Verification] — Test in QEMU (angband-style)
```

**Relevance to angband**: angband currently starts from known CVEs. Adding Syzkaller integration would enable "CVE-less" exploitation: find a bug with Syzkaller, automatically generate an exploit.

### Dr. Checker (USENIX Security 2018)

**Paper**: Machiry et al., "Dr. Checker: A Soundy Analysis for Linux Kernel Drivers"

**Approach**: Static analysis that finds bug classes in kernel drivers without running them.

**Relevance to angband (LOW)**: Could help identify vulnerable objects and their sizes, but angband primarily targets core kernel, not drivers.

## Systematization & Taxonomies

### SoK: AEG (EuroS&P 2020)

Systematization of Knowledge paper surveying 10 years of AEG research.

**Key taxonomy**:
```
Exploit Generation Systems
├── Target: Userspace | Kernel | Firmware
├── Bug Source: Source code | Binary | Crash report
├── Bug Class: Stack overflow | Heap overflow | UAF | Race | Logic
├── Approach: Symbolic execution | Fuzzing | Pattern matching | LLM
├── Output: Metasploit module | Python script | C source | Assembly
└── Verification: Replay | Oracle | Manual review
```

**Relevance to angband**: Places angband in the AEG landscape:
- Target: Kernel
- Bug Source: Known CVE (extending to Syzkaller crash reports)
- Bug Class: Primarily UAF (extending to all classes)
- Approach: Pattern matching + template code generation
- Output: C source → compiled binary
- Verification: QEMU guest execution + vuln_drill module

## Technique → angband Stage Mapping

### How Each AEG Technique Maps to angband's 7-Stage Pipeline

| AEG System | angband Stage | Integration Opportunity |
|-----------|--------------|----------------------|
| **FUZE UAF Classification** | Stage 2 (Trigger) | Auto-classify UAF type from patch diff |
| **FUZE Heap Planning** | Stage 2 (Groom) | Auto-compute spray parameters (size, count) |
| **KOOBE Capability Amplification** | Stage 5 (Primitive) | Auto-discover multi-step exploitation chains |
| **KOOBE Interaction Graph** | Stage 5 (Primitive) | Find novel code paths for func ptr hijack |
| **SLAKE Slab Modeling** | Stage 2 (Groom) | Predict exact reclaim location (eliminate offset scanning) |
| **SLAKE Allocation Planning** | Stage 2 (Groom) | Generate optimal spray sequence |
| **HEAPO Optimization** | Stage 2 (Groom) | Minimize spray count for reliability |
| **Mayhem Symbolic Execution** | Stage 3 (Trigger) | Auto-generate trigger inputs for race windows |
| **AEG Constraint Solving** | Stage 5 (Primitive) | Auto-solve "what value at what offset?" for msg_msg |
| **Gollum LLM Guidance** | All stages | LLM suggests technique selection for each stage |
| **FUZE Primitive Ranking** | Stage 6 (Escalate) | Auto-select best escalation path (modprobe vs commit_creds) |

## Implementation Roadmap for angband

### Phase 1: Spray Parameter Automation (P0)

**Integrate SLAKE/HEAPO concepts into vuln_analyzer.py**:

```python
# Current: hard-coded spray parameters
"spray_count": 256,
"spray_msg_size": 208

# Future: auto-computed from target analysis
def compute_spray_params(target_object_size: int, 
                         target_cache: str,
                         object_count: int) -> SprayConfig:
    slab = model_slub_state(target_cache)
    needed = compute_reclaim_count(object_count, slab)
    return SprayConfig(count=needed, size=target_object_size - 48)
```

### Phase 2: Multi-Path Exploitation (P0)

**KOOBE-style capability amplification in angband/chaining/**:
- Auto-discover alternative exploitation chains
- Parallel execution of modprobe_path + commit_creds paths
- Fallback: if modprobe blocked, try commit_creds

### Phase 3: Auto-Trigger Generation (P1)

**Mayhem-style symbolic execution for trigger inputs**:
- Given a CVE's race condition description
- Use concolic execution to find winning race windows
- Auto-generate the multi-threaded trigger code

### Phase 4: LLM-Assisted Code Generation (P2)

**Gollum-style stage decomposition**:
- LLM proposes technique for each stage
- Template generates candidate code
- QEMU testing provides feedback
- Iterate until exploitation succeeds

### Phase 5: Syzkaller Integration (P3)

**Bridge bug finding to exploitation**:
- Consume Syzkaller crash reports
- Auto-classify bug type, affected object, slab cache
- Feed into angband's CVE analysis pipeline
- Generate exploit automatically

## Key References

| Paper/Project | Year | Venue | URL |
|--------------|------|-------|-----|
| AEG: Automatic Exploit Generation | 2011 | NDSS | cs.cmu.edu/~aavgerin/papers/aeg-ndss-2011.pdf |
| Mayhem DARPA CGC | 2016 | DARPA | forallsecure.com |
| FUZE: Kernel UAF Exploitation | 2018 | USENIX Security | syssec.kaist.ac.kr/pub/2018/fuze_sec18.pdf |
| KOOBE | 2020 | USENIX Security | chengyusong.me/publications/koobe_sec20.pdf |
| SLAKE | 2021 | CCS | chengyusong.me/publications/slake_ccs21.pdf |
| HEAPO | 2021 | - | Automated heap layout |
| SoK: AEG | 2020 | EuroS&P | IEEE |
| Dr. Checker | 2018 | USENIX Security | ssl.engineering.nyu.edu |
| Gollum | 2023 | USENIX Security | seanheelan.io |
| Syzkaller | 2018+ | - | github.com/google/syzkaller |
| angr | 2015+ | - | github.com/angr/angr |

## angband in the AEG Landscape

```
                     Bug Finding                    Exploit Generation
                    ─────────────                   ──────────────────
Source Code    →    [Syzkaller]        →           [angband]
                [KASAN/KMSAN]                    [FUZE/KOOBE]
                [Dr. Checker]                    [SLAKE/HEAPO]
                                                      ↓
Binary         →    [Mayhem/AEG]       →         [angr-based]
                [CGC Challenge]                 [AEG constraint solve]
                                                      ↓
Crash Report   →    [Syzkaller C-repro] →       [angband]
                [CGC CRS]                       [Gollum LLM]
```

angband sits at the **exploit generation** end: given a known vulnerability (CVE or Syzkaller crash), it generates a working exploit. The AEG research (FUZE, KOOBE, SLAKE) provides techniques to automate the intermediate steps angband currently does manually (spray parameter selection, offset computation, trigger generation).
