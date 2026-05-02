# Angband -- QEMU Target Preparation & Test Execution

Generated exploits must NEVER run on the host.  Angband uses an isolated
QEMU VM for all execution.  This document walks through every step from a
bare host to a verified demo run.

---

## Prerequisites

| Package              | Why it's needed                            | Install                                       |
|----------------------|--------------------------------------------|-----------------------------------------------|
| `qemu-system-x86`   | VM hypervisor                              | `sudo apt install qemu-system-x86`            |
| `cloud-image-utils`  | `cloud-localds` to create the seed image   | `sudo apt install cloud-image-utils`           |
| `openssh-client`     | `ssh-keygen` and `ssh` for guest access    | Usually pre-installed                          |
| `python3` + `pip`    | Angband CLI                                | `sudo apt install python3 python3-pip python3-venv` |
| `gcc`                | Compile the generated exploit C code       | `sudo apt install gcc`                         |
| `telnet` (optional)  | Serial console access for debugging        | `sudo apt install telnet`                      |

Install everything at once:

```bash
sudo apt-get update
sudo apt-get install -y qemu-system-x86 cloud-image-utils openssh-client \
                        python3 python3-pip python3-venv gcc telnet
```

---

## Step 1 -- Install Angband

```bash
cd /path/to/angband
python3 -m venv venv
source venv/bin/activate
pip install -e .
```

Verify:

```bash
angband --version
# angband, version 0.1.0
```

---

## Step 2 -- Prepare the QEMU Target Image

```bash
bash harness/setup.sh
```

This is a **one-time** operation.  It will:

1. **Check host dependencies** -- verifies `qemu-img`, `cloud-localds`, etc.
2. **Download the Ubuntu 24.04 cloud image** (~600 MB, cached in
   `mordor_run/cache/`).  This file is never modified.
3. **Generate an SSH key pair** under `mordor_run/ssh/`.
4. **Create a cloud-init seed image** (`mordor_run/harness/seed.img`) that
   provisions the guest with:
   - User `ubuntu` (password `ubuntu`, passwordless sudo)
   - Your SSH public key for key-based auth
   - Auto-mount of the host repository at `/mnt/angband` via 9p
5. **Create a qcow2 overlay snapshot** (`mordor_run/harness/disk.qcow2`)
   backed by the base image.  All guest writes go into this overlay;
   the base image stays pristine.

The resulting layout:

```
mordor_run/
├── cache/
│   └── ubuntu-24.04-server-cloudimg-amd64.img   ← pristine base (never modified)
├── harness/
│   ├── disk.qcow2                                ← overlay snapshot (all guest writes)
│   └── seed.img                                  ← cloud-init provisioning
└── ssh/
    ├── id_ed25519                                ← private key
    └── id_ed25519.pub                            ← public key
```

---

## Step 3 -- Launch the VM

```bash
bash harness/launch.sh
```

This will:

1. Boot QEMU in the background with KVM acceleration (if available)
2. Wait for SSH to become accessible on `localhost:2222`
3. Report when the VM is ready

**First boot takes ~60-90 seconds** because cloud-init needs to run.
Subsequent boots (after `stop.sh` without `reset.sh`) are faster (~20s).

### Connect to the VM

**SSH** (preferred):
```bash
ssh -o StrictHostKeyChecking=no -i mordor_run/ssh/id_ed25519 -p 2222 ubuntu@localhost
```

**Serial console** (useful if SSH is down or kernel panics):
```bash
bash harness/console.sh
# or: telnet localhost 4444
```

### Verify the 9p mount

Inside the guest:
```bash
ls /mnt/angband/
# Should show the angband repository files
```

If the 9p mount is missing:
```bash
sudo mount -t 9p -o trans=virtio,version=9p2000.L host0 /mnt/angband
```

---

## Step 4 -- Initialize and Generate the Payload

From the **host**:

```bash
source venv/bin/activate

# Demo mode (safe walkthrough with vuln_drill)
angband init demo
angband generate

# Or: CVE analysis mode
angband init CVE-2024-1086
angband generate
```

This creates:
- `mordor_run/current/exploit.yaml` -- scenario configuration
- `mordor_run/current/exploit.c` -- generated C source
- `mordor_run/current/exploit` -- compiled binary (statically linked)

---

## Step 5 -- Run the Automated Verification

```bash
bash run_and_verify.sh
```

This script handles everything:

1. Generates the payload (if not already done)
2. Waits for the VM to be accessible via SSH
3. Mounts 9p inside the guest
4. Builds and loads `vuln_drill.ko` in the guest (demo mode only)
5. Runs the exploit binary inside the guest
6. Extracts `dmesg` and `/proc/vuln_drill` output
7. Verifies success criteria

### Success Criteria (Demo Mode)

| Check | File | Expected |
|-------|------|----------|
| Exploit completed | `exploit_run.log` | Contains `EXPLOIT COMPLETE` |
| Privilege escalation | `exploit_run.log` | Contains `PRIVILEGE ESCALATION SUCCESSFUL` |
| Root achieved | `exploit_run.log` | Contains `uid=0 euid=0` |
| All stages received | `dmesg_tail.log` | Contains `vuln_drill: stage <X> received` for all 7 stages |
| Correct order | `vuln_drill_status.log` | `sequence_complete: yes` |
| Kernel confirms | `dmesg_tail.log` | Contains `ESCALATE SUCCESS` |

### Success Criteria (CVE Mode)

| Check | File | Expected |
|-------|------|----------|
| Payload completed | `exploit_run.log` | Contains `EXPLOIT COMPLETE` or `DEMO COMPLETE` |
| Privilege escalation | `exploit_run.log` | Contains `PRIVILEGE ESCALATION SUCCESSFUL` |
| Root achieved | `exploit_run.log` | Contains `uid=0 euid=0` |
| Kernel panic | serial log | No panic messages |

---

## Testing CVE-2026-23209 (macvlan UAF)

The CVE-2026-23209 exploit requires user namespaces with network privileges. On Ubuntu,
the default kernel restricts these. To test:

### Enable Permissive Kernel Settings (requires sudo in guest)

```bash
# Inside the guest, as sudo:
sudo sysctl -w kernel.unprivileged_userns_clone=1
sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0
```

### Build and Run

```bash
# From host:
source venv/bin/activate
angband init CVE-2026-23209 --target ubuntu-24.04-x86_64
angband generate

# From guest:
scp -P 2222 -i mordor_run/ssh/id_ed25519 localhost:/path/to/angband/mordor_run/current/cve_2026_23209 /tmp/
chmod +x /tmp/cve_2026_23209
/tmp/cve_2026_23209
```

### Expected Output

```
[*] ===== Stage: prep =====
[*] ===== Stage: groom =====
[*] ===== Stage: trigger =====
[+] UAF triggered: net_device freed
[*] ===== Stage: leak =====
[+] KASLR bypass: kernel_base = 0xffffffff...
[*] ===== Stage: primitive =====
[*] PTE reclaim + dirty pagetable write
[*] ===== Stage: escalate =====
[*] modprobe_path overwrite
[+] ROOT ACHIEVED via modprobe_path!
[+] PRIVILEGE ESCALATION SUCCESSFUL
[+] uid=0 euid=0 gid=0 egid=0
```

---

## Step 6 -- Manual Inspection (Optional)

SSH into the guest and run commands manually:

```bash
ssh -o StrictHostKeyChecking=no -i mordor_run/ssh/id_ed25519 -p 2222 ubuntu@localhost

# Inside the guest:
cd /mnt/angband

# Run the exploit
./mordor_run/current/cve_2026_23209

# Check kernel logs
sudo dmesg | grep 'vuln_drill:'

# Read vuln_drill status
cat /proc/vuln_drill

# Load vuln_drill manually if needed
cd /mnt/angband/module/vuln_drill
make
sudo insmod ./vuln_drill.ko
```

---

## VM Lifecycle Commands

| Action | Command |
|--------|---------|
| First-time setup | `bash harness/setup.sh` |
| Boot the VM | `bash harness/launch.sh` |
| Stop the VM | `bash harness/stop.sh` |
| Reset to clean state | `bash harness/reset.sh` |
| Import custom VM | `bash harness/import.sh <image>` |
| Serial console | `bash harness/console.sh` |

---

## Using Your Own QEMU Image

If you have your own QEMU VM image (installed manually, a custom kernel
build, etc.), you can integrate it into the angband pipeline.

### Requirements

Your VM must have:
- SSH server running (OpenSSH)
- A user account with `sudo` access (passwordless preferred)
- `build-essential` and kernel headers for building `vuln_drill.ko`
- Network accessible via QEMU port forwarding

### Step 1: Import the Image

```bash
bash harness/import.sh /path/to/your-vm.qcow2 [ssh-port] [ssh-user]
```

Example:
```bash
bash harness/import.sh ~/my-kernel-vm.qcow2 2222 testuser
```

This will:
1. Generate angband SSH keys under `mordor_run/ssh/`
2. Display the public key for you to add to your VM
3. Create a qcow2 overlay snapshot (your original image is never modified)

### Step 2: Add the SSH Key to Your VM

The script prints a public key. You must add it to your VM's
`~/.ssh/authorized_keys`. If your VM is currently running:

```bash
# Copy the key to the VM (adjust port and user as needed)
ssh -p 2222 youruser@localhost \
  'mkdir -p ~/.ssh && chmod 700 ~/.ssh && cat >> ~/.ssh/authorized_keys' \
  <<< 'ssh-ed25519 AAAA... (the key printed by import.sh)'
```

Or boot your VM, log in via the console, and paste the key manually.

### Step 3: Launch Your VM with Angband

If your VM is NOT already running, use angband's launcher:

```bash
bash harness/launch.sh
```

If your VM IS already running with its own QEMU command, make sure it has:
- SSH port forwarding: `-net user,hostfwd=tcp::2222-:22`
- 9p mount (optional but recommended): `-virtfs local,path=/path/to/angband,mount_tag=host0,security_model=passthrough`

### Step 4: Verify Connectivity

```bash
ssh -o StrictHostKeyChecking=no \
    -i mordor_run/ssh/id_ed25519 \
    -p 2222 youruser@localhost \
    'uname -r && id'
```

### Step 5: Set Up 9p Mount (if your VM supports it)

Inside the guest:
```bash
sudo mkdir -p /mnt/angband
sudo mount -t 9p -o trans=virtio,version=9p2000.L host0 /mnt/angband
```

If 9p is not available (e.g., your QEMU was launched without `-virtfs`),
you can copy the exploit binary via `scp` instead:

```bash
# On the host, after 'angband generate':
scp -i mordor_run/ssh/id_ed25519 -P 2222 \
    mordor_run/current/exploit youruser@localhost:/tmp/exploit
```

### Step 6: Run the Exploit

With 9p:
```bash
bash run_and_verify.sh
```

Without 9p (manual):
```bash
# Copy exploit and module to guest
scp -i mordor_run/ssh/id_ed25519 -P 2222 \
    mordor_run/current/exploit youruser@localhost:/tmp/

# SSH in and run
ssh -i mordor_run/ssh/id_ed25519 -p 2222 youruser@localhost
cd /tmp && chmod +x exploit && ./exploit
```

### Resetting the VM

If the VM gets into a bad state (kernel panic, corrupted filesystem,
wrong SSH keys), reset it instantly:

```bash
bash harness/reset.sh
bash harness/launch.sh
```

This destroys the overlay snapshot and creates a fresh one from the
pristine base image.  No re-download needed.  Cloud-init will re-run
on the next boot to provision SSH keys and the 9p mount.

---

## Troubleshooting

### SSH key rejected / password prompt

The SSH key was generated after the VM was already provisioned.  Fix:

```bash
bash harness/stop.sh
bash harness/reset.sh
bash harness/launch.sh
```

### VM boots but SSH times out

1. Check if QEMU is running: `cat mordor_run/harness/qemu.pid && ps -p $(cat mordor_run/harness/qemu.pid)`
2. Check QEMU log: `cat mordor_run/harness/qemu.log`
3. Try the serial console: `bash harness/console.sh`
4. If using software emulation (no KVM), boot takes much longer (~3-5 minutes)

### Port 2222 already in use

Another VM or service is using the port:

```bash
ss -tlnp | grep :2222
# Kill the conflicting process, or stop the other VM
bash harness/stop.sh
```

### 9p mount fails inside guest

Ensure QEMU was launched with the `-virtfs` flag (handled by `launch.sh`).
Try mounting manually:

```bash
sudo mount -t 9p -o trans=virtio,version=9p2000.L host0 /mnt/angband
```

### vuln_drill.ko fails to build

The guest needs kernel headers:

```bash
sudo apt-get update
sudo apt-get install -y build-essential linux-headers-$(uname -r)
cd /mnt/angband/module/vuln_drill
make clean && make
sudo insmod ./vuln_drill.ko
```

### "No space left on device" in the guest

The overlay is 10 GB.  If that's insufficient:

```bash
# On the host, after stopping the VM:
qemu-img resize mordor_run/harness/disk.qcow2 +10G
# Then boot and resize the partition inside the guest
```

---

## Cleanup

Remove all generated state (keeps the cached base image):

```bash
bash cleanup.sh
```

Remove everything including the cached Ubuntu image (~600 MB):

```bash
bash cleanup.sh --all
```
