"""Vulnerable kernel module for exploit development and testing.

Exposes configurable bugs (UAF, OOB, double-free, races) via ioctl/procfs.
Supports Ubuntu 24.04 and 26.04, x86_64 and arm64.
"""