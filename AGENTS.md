# Angband Agent Instructions

This document provides high-signal context for OpenCode agents working in the `angband` repository. It focuses on non-obvious setup requirements, expected workflows, and critical safety rules.

## Core Architecture and Entrypoints
*   **Purpose**: Angband is a modular framework for Linux kernel exploit development, heavily relying on automated generation of PoCs from YAML configs and isolated execution.
*   **Entrypoint**: The main CLI tool is `cli.py`, which is installed as the `angband` command via `pyproject.toml`. Do not invoke `cli.py` directly; install the package in editable mode and use the `angband` command.
*   **Structure**: 
    *   Python core logic: `core/`, `generators/`, `cli.py`.
    *   C exploit primitives: `primitives/`.
    *   Generated output: `exploit.yaml` (configuration) and `exploit.c` (generated from `templates/exploit.c.jinja2`).
    *   Vulnerable testing module: `module/vuln_drill/`.

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
**CRITICAL**: *Never* run generated exploit binaries (`exploit`) on the host machine. The framework is designed to target kernels and will likely crash or compromise the host if executed outside the test environment.

1.  **Exploit Execution Workflow**:
    *   Exploits must be run inside the QEMU harness.
    *   The standard execution flow is to use the `run_and_verify.sh` script, which handles generation, QEMU interaction via SSH, and log extraction.
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
*   **Generating an Exploit Configuration**:
    ```bash
    angband init <cve_or_commit> --target <target-name>
    ```
    *Example*: `angband init CVE-2023-1234 --target ubuntu-26.04-x86_64`
*   **Generating the C Payload**:
    ```bash
    angband generate
    ```
    *Note: This reads `exploit.yaml`, generates `exploit.c` using Jinja2 templates, and attempts compilation linking with `primitives/`.*

## Modifying the Codebase
*   When editing Python code (e.g., `generators/poc_gen.py`), test changes by regenerating the exploit: `angband generate`.
*   When modifying C primitives (`primitives/*.c`), ensure the `angband generate` compilation step succeeds.
*   Log artifacts (`exploit_run.log`, `dmesg_tail.log`) are generated in the project root by `run_and_verify.sh`. Inspect these to debug test failures.