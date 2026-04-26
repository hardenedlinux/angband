# Angband - Kernel Exploit Framework

**A staged, modular framework for Linux kernel exploit development and PoC automation.**

## Setup & Quick Start

**1. Install System Dependencies**
```bash
sudo apt-get update
sudo apt-get install -y qemu-system-x86 cloud-image-utils telnet
```

**2. Setup Python Environment**
```bash
python3 -m venv venv
source venv/bin/activate
pip install -e .
```

**3. Initialize and Run**
```bash
angband init CVE-2023-1234
angband generate
```

## Features
- **Clear stage separation**: Grooming, Trigger, Leak, Primitive, Escalation, Cleanup
- **Automation**: `angband new <type>` generates YAML configs + C skeletons
- **Vulnerable test module**: `module/vuln_drill/` (build & load for safe testing)
- **Modern mitigations aware**: CFI, CET, PAC, KASLR, SMEP/SMAP
- **Focus**: Reliability through grooming. Prefers data-only attacks (DirtyCred, page table).

## Workflow

```text
┌─────────────────┐    angband init     ┌───────────────┐
│ CVE / Bug       ├────────────────────►│ exploit.yaml  │
└─────────────────┘                     └───────┬───────┘
                                                │
                               angband generate │
                                                ▼
┌─────────────────┐       GCC           ┌───────────────┐
│ exploit binary  │◄────────────────────┤ exploit.c     │
└────────┬────────┘                     └───────────────┘
         │
         │ run_and_verify.sh (via SSH & 9p)
         ▼
╔═══════════════════════════════════════════════════════╗
║                 QEMU Test Environment                 ║
║                                                       ║
║  ┌──────────────┐         ┌────────────────────────┐  ║
║  │ vuln_drill.ko│◄────────┤ Executes against OS    │  ║
║  └──────────────┘         └────────────────────────┘  ║
╚═══════════════════════════════════════════════════════╝
         │
         │ extracts results
         ▼
┌─────────────────┐
│ exploit_run.log │
│ dmesg_tail.log  │
└─────────────────┘
```

## Current Status
- **Core engine** and grooming stage implemented.
- **Armory (C Primitives)**: Initial library for `msg_msg`, `pipe_buffer`, and `dirty_cred` primitives ready.
- **Vulnerable kernel module**: `module/vuln_drill/` ready (supports UAF/OOB for testing all stages).
- **CLI + venv** setup complete.

### Primitives in the Armory:
- `msg_msg.c`: Spraying and allocation helpers.
- `pipe_buffer.c`: Pipe-based heap allocation and spraying.
- `dirty_cred.c`: Credential spraying via user namespaces.

Build & load the test module:
```bash
cd module/vuln_drill
make
sudo insmod vuln_drill.ko
```

## Manual Verification in QEMU

If you encounter networking issues or SSH connection resets with `run_and_verify.sh`, you can test manually by logging into the VM:

1. Connect to QEMU via SSH:
   ```bash
   ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -i .ssh_key -p 2222 ubuntu@localhost
   ```
2. Navigate to the 9p mount where the framework is shared:
   ```bash
   cd /mnt/angband
   ```
3. Run the generated exploit:
   ```bash
   ./exploit
   ```
4. Check the kernel logs for faults:
   ```bash
   dmesg | tail -n 50
   ```

See `exploit.yaml` for example configuration.

**Next**: Expand primitives (pipe_buffer, dirty_cred), QEMU harness for Ubuntu 26.04, full PoC generator.