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
