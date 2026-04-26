# Angband Test Execution Instructions

You should never run the generated exploits directly on your host machine. Always test them in the isolated QEMU environment.

## 1. Prepare the Test Environment
Ensure you have the required QEMU utilities installed (`sudo apt install qemu-system-x86 cloud-image-utils`).
Start the QEMU VM in the background (or in a separate terminal):
```bash
cd /home/john/kernel-exp-framework/angband/harness
./setup.sh
./launch.sh
```
*Note: The script automatically generates SSH keys, creates a cloud-init seed, and mounts the angband directory into the VM via 9p at `/mnt/angband`.*

## 2. Automated Exploit Execution and Verification
Once the VM is running, use the automated script to generate the exploit, execute it inside the VM via SSH, and collect the logs.
```bash
cd /home/john/kernel-exp-framework/angband
./run_and_verify.sh
```

## 3. Analysis
The `run_and_verify.sh` script produces two files:
- `exploit_run.log`: Contains the STDOUT/STDERR from the exploit execution.
- `dmesg_tail.log`: Contains the last 50 lines of the kernel message buffer from the VM, which is crucial for analyzing page faults, SLUB corruption, or panic traces if the exploit failed.

To exit QEMU (if running in foreground), use `Ctrl+A, X`.