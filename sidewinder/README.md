# sidewinder

Userland side-channel and Rowhammer vulnerability hunting toolkit. No kernel modules, no eBPF, no root required (for detection). Targets x86_64 Linux.

## Quick Start

```bash
python3 -m venv venv && source venv/bin/activate
pip install -e .
make -C c_primitives       # Build native C library
sidewinder detect          # Run system scan
```

## Commands

| Command | Description | Safety |
|---------|-------------|--------|
| `sidewinder detect` | CPU/DRAM fingerprinting, CVE matching, mitigation status | Read-only |
| `sidewinder probe side-channel` | Flush+Reload, Prime+Probe calibration | Read-only |
| `sidewinder probe speculative` | Spectre v1, Meltdown, Zenbleed, Downfall, TSA tests | Read-only |
| `sidewinder probe rowhammer --time 60` | Blacksmith frequency-based hammer fuzzing | May cause system instability |
| `sidewinder exploit kaslr` | KASLR bypass (kallsyms or side-channel) | Read-only |
| `sidewinder exploit credential-leak` | Info leak via cache/Meltdown/TSA | Read-only |
| `sidewinder exploit rowhammer-escalation --scenario vm` | PTE flip → privilege escalation | **VM only** |
| `sidewinder auto --scenario vm` | Full pipeline: detect → probe → exploit | **VM only** |
| `sidewinder report --format markdown` | Human-readable vulnerability report | Read-only |
| `bash cleanup.sh` | Kill processes, release huge pages, clean temp files | Host cleanup |

## Safety Model

```
--scenario host  :  detect + probe + info leak   (NO writes, NO escalation)
--scenario vm    :  detect + probe + info leak + escalation  (PTE flips, credential overwrite)
```

Host mode NEVER modifies system state. VM mode requires explicit confirmation.

## Attacks Covered

### Detection (passive)
- CPUID-based microarchitecture identification (40+ Intel/AMD profiles)
- `/sys/devices/system/cpu/vulnerabilities/*` parsing
- Kernel mitigation status (PTI, IBRS, STIBP, IBPB, Retpoline, RSB filling)
- DRAM type detection (DDR3/4/5, ECC status)
- CVE profile matching (20+ CVEs)

### Probing (active)
- Cache side-channel: Flush+Reload, Prime+Probe, auto-threshold calibration
- Speculative execution: Spectre v1, Meltdown viability, Zenbleed (Zen 2), Downfall/GDS (Intel AVX2)
- TSA (Transient Scheduler Attack): Scheduler-based data leak on AMD Zen 3/4
- GhostRace detection: speculative race-condition viability
- BHI (Branch History Injection) detection
- Rowhammer: Blacksmith-style frequency-based fuzzer, DRAM address RE

### Exploitation (VM scenario)
- KASLR bypass: kallsyms → prefetch side-channel fallback
- Credential leak: Meltdown physical read, TSA sibling-thread leak, generic cache leak
- Rowhammer escalation: PTE bit-flip, modprobe_path overwrite, credential corruption

## Architecture

```
CLI (click) → Python modules → ctypes → libsidewinder.so
                                         ↓
            cache.c  timer.c  memory.c  hammer.c
            (Flush+Reload, RDTSC, huge pages, frequency hammer)
```

## Development

See [AGENTS.md](AGENTS.md) for detailed architecture, C API reference, and contribution guide.

## Requirements

- Linux x86_64 (kernel 4.15+)
- Python 3.10+
- GCC (for C primitives)
- Optional: sudo (for huge pages, MSR reads, pagemap access)

## References

- Mastik: [0xADE1A1DE/Mastik](https://github.com/0xADE1A1DE/Mastik) — cache attack primitives
- Blacksmith: [comsec-group/blacksmith](https://github.com/comsec-group/blacksmith) — frequency-based Rowhammer
- ZenHammer: [comsec-group/zenhammer](https://github.com/comsec-group/zenhammer) — AMD Rowhammer + DDR5
- DRAMA: [IAIK/drama](https://github.com/IAIK/drama) — DRAM address reverse engineering
- Transient Fail: [IAIK/transientfail](https://github.com/IAIK/transientfail) — transient execution PoC collection
- spectre-meltdown-checker: [speed47/spectre-meltdown-checker](https://github.com/speed47/spectre-meltdown-checker) — 32+ CVE vulnerability scanner

## License

MIT
