# angband/chaining/__init__.py
"""Exploit chaining and vulnerability pipelining module.

This module implements the capability-based exploit chaining system
that allows multiple CVEs to be combined into a single exploitation
pipeline.

Key concepts:
- Capability: Something a stage provides or requires (e.g., kaslr_bypass, write_primitive)
- Pipeline: A sequence of CVE stages that flow from capability to privilege escalation
- Context: Shared state that passes between chained CVEs
"""

from .capabilities import CapabilityChecker, Capability, CAPABILITY_REGISTRY
from .orchestrator import ExploitChain, PipelineStage
