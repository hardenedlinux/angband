# Angband Agent Instructions

This document provides high-signal context for OpenCode agents working in the `angband` repository. It focuses on non-obvious setup requirements, expected workflows, and critical safety rules.

## Core Architecture and Entrypoints
*   **Purpose**: Angband is an automated kernel exploit generation framework. Its goal is to produce full-chain kernel exploits from CVE identifiers to accelerate severity analysis. Currently, it generates staged demo payloads (simulation-only), runs them in an isolated QEMU guest, and verifies kernel-side stage evidence through the synthetic `vuln_drill` module. Real exploit generation is the next milestone.
*   **Entrypoint**: The main CLI tool is the installed `angband` command. Do not invoke repo-local scripts directly when the package entrypoint is available; install in editable mode and use `angband`.
*   **Structure**:
    *   Python package logic: `angband/`.
    *   C exploit reference primitives: `primitives/`.
    *   Generated runtime output: `mordor_run/current/exploit.yaml`, `mordor_run/current/exploit.c`, `mordor_run/current/exploit`.
    *   Synthetic testing module: `module/vuln_drill/`.

## Environment Setup
Agents should establish a clean Python environment from scratch to ensure predictable behavior, rather than assuming external dependencies exist.

1.  **Create and activate a virtual environment:**
    ```bash
    python3 -m venv venv
    source venv/bin/activate
    ```
2.  **Install the project in editable mode:**
    ```bash
    pip install -e .
    ```
    *This creates the `angband` entrypoint which correctly resolves module paths (e.g., `angband.core.engine`).*

## Test Execution & Safety Conventions
**CRITICAL**: The generated payload is currently non-operational (simulation-only), but the project goal is full-chain exploit generation. Always treat `mordor_run/current/exploit` as guest-only output. Never run it on the host machine.

1.  **Demo Execution Workflow**:
    *   The standard flow is to use `run_and_verify.sh`, which handles generation, QEMU interaction via SSH, and log extraction.
    *   In `angband init demo` mode, it also builds and loads `module/vuln_drill/vuln_drill.ko` in the guest.
    *   In `angband init <CVE>` mode, the CVE is metadata only and `run_and_verify.sh` skips guest kernel-module setup.
    ```bash
    # Assuming venv is active and QEMU harness is running in background
    ./run_and_verify.sh
    ```
2. **QEMU Harness Execution**:
    *   The harness is located in `harness/setup.sh`, `harness/launch.sh`, and `harness/stop.sh`. It requires `qemu-system-x86` and `cloud-image-utils` (`sudo apt install qemu-system-x86 cloud-image-utils`).
    *   Initialize the VM: `cd harness && ./setup.sh`
    *   Launch the VM: `./launch.sh`
    *   Connect to the Serial Console: `./console.sh` (useful if kernel panics and SSH drops)
    *   Stop the VM: `./stop.sh`
    *   The harness creates a 9p mount point, making the host's `angband` directory available inside the VM at `/mnt/angband`.

## Common Workflows & Commands
*   **Generating a Demo Configuration**:
    ```bash
    angband init <cve_or_commit> --target <target-name>
    ```
    *Examples*:
    *   `angband init demo --target ubuntu-24.04-x86_64`
    *   `angband init CVE-2024-1086 --target ubuntu-24.04-x86_64`
*   **Generating the C Payload**:
    ```bash
    angband generate
    ```
    *Note: This reads `mordor_run/current/exploit.yaml`, generates `mordor_run/current/exploit.c` using Jinja2 templates, and compiles `mordor_run/current/exploit`.*

## Modifying the Codebase
*   When editing Python code, test changes by regenerating the payload with `angband generate`.
*   When modifying C primitives (`primitives/*.c`), ensure the `angband generate` compilation step succeeds.
*   Demo verification artifacts are written under `mordor_run/current/`:
    *   `exploit_run.log`
    *   `dmesg_tail.log`
    *   `vuln_drill_status.log` in demo mode
