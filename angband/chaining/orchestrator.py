# angband/chaining/orchestrator.py
"""Exploit chain orchestrator for multi-CVE pipelines.

The orchestrator takes a chain configuration (list of CVEs with
roles) and executes them sequentially, passing capabilities and
data between stages via shared context.
"""

from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

from .capabilities import (
    Capability,
    CapabilityChecker,
    STAGE_CAPABILITIES,
)


@dataclass
class PipelineStage:
    """A single stage in an exploit pipeline."""
    name: str                              # e.g., "groom", "trigger", "leak"
    method: str                            # e.g., "timerfd_spray"
    cve_id: Optional[str] = None           # Which CVE provides this stage
    provides: List[str] = field(default_factory=list)
    requires: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    output: Dict[str, Any] = field(default_factory=dict)


@dataclass
class PipelineResult:
    """Result of executing a pipeline."""
    success: bool
    final_stage: str
    capabilities_achieved: List[str]
    capabilities_missing: List[str]
    root_achieved: bool = False
    logs: List[str] = field(default_factory=list)
    error: Optional[str] = None


class ExploitChain:
    """Orchestrates multi-CVE exploit chains.

    Example chain config:
    ```python
    chain_config = {
        "name": "timerfd_full_chain",
        "cves": [
            {
                "cve": "CVE-2026-XXXX",
                "role": "capability_provider",
                "provides": ["CAP_SYS_TIME"],
            },
            {
                "cve": "CVE-2026-35555",
                "role": "primitive_provider",
                "requires": ["CAP_SYS_TIME"],
                "provides": ["KERNEL_CODE_EXEC", "KERNEL_WRITE"],
            },
            {
                "cve": "builtin",
                "role": "escalation",
                "requires": ["KERNEL_WRITE", "MODPROBE_PATH_ADDR"],
                "escalation": "modprobe_path",
            },
        ],
    }
    ```
    """

    def __init__(self, chain_config: Dict):
        self.config = chain_config
        self.name = chain_config.get("name", "unnamed_chain")
        self.cves = chain_config.get("cves", [])
        self.checker = CapabilityChecker()
        self.stages: List[PipelineStage] = []
        self.logs: List[str] = []
        self._build_pipeline()

    def _build_pipeline(self) -> None:
        """Parse chain config into pipeline stages."""
        for cve_step in self.cves:
            cve_id = cve_step.get("cve", "unknown")
            role = cve_step.get("role", "unknown")
            requires = cve_step.get("requires", [])
            provides = cve_step.get("provides", [])
            escalation = cve_step.get("escalation")
            stages_list = cve_step.get("stages", [])

            if stages_list:
                # Explicit stage definitions
                for stage in stages_list:
                    self.stages.append(PipelineStage(
                        name=stage["name"],
                        method=stage.get("method", stage["name"]),
                        cve_id=cve_id,
                        provides=stage.get("provides", []),
                        requires=stage.get("requires", []),
                    ))
            elif escalation:
                # Escalation-only CVE
                self.stages.append(PipelineStage(
                    name="escalate",
                    method=escalation,
                    cve_id=cve_id,
                    provides=["ROOT_SHELL"],
                    requires=requires,
                ))
            else:
                # Standard 6-stage CVE
                standard_stages = [
                    "groom", "trigger", "leak", "primitive"
                ]
                for stage_name in standard_stages:
                    key = f"{cve_step.get('cve_profile', cve_id)}_{stage_name}"
                    caps = STAGE_CAPABILITIES.get(key, ([], []))
                    req_caps, prov_caps = caps
                    self.stages.append(PipelineStage(
                        name=stage_name,
                        method=stage_name,
                        cve_id=cve_id,
                        provides=[c.name for c in prov_caps],
                        requires=[c.name for c in req_caps],
                    ))

    def validate(self) -> Tuple[bool, List[str]]:
        """Validate that all stages have their requirements met."""
        issues = []
        available = set()

        for stage in self.stages:
            for req in stage.requires:
                if req not in available:
                    issues.append(
                        f"Stage '{stage.name}' ({stage.cve_id}) "
                        f"requires '{req}' but it is not yet available"
                    )
            for prov in stage.provides:
                available.add(prov)

        return len(issues) == 0, issues

    def execute_stage(self, stage: PipelineStage,
                      run_fn: Optional[Callable] = None) -> bool:
        """Execute a single pipeline stage.

        Args:
            stage: The pipeline stage to execute
            run_fn: Optional function (stage, context) -> result_dict.
                   If None, this is a dry-run that just grants capabilities.

        Returns:
            True if stage succeeded, False if it failed or was skipped
        """
        self.logs.append(f"[*] Stage: {stage.name} ({stage.cve_id or 'builtin'})")

        # Check requirements
        ok, msg = self.checker.can_execute_stage({
            "requires": stage.requires,
        })
        if not ok:
            self.logs.append(f"[!] SKIPPED: {msg}")
            return False

        self.logs.append(f"[+] Capabilities OK: {stage.requires or 'none'}")

        # Execute (or dry-run)
        if run_fn:
            result = run_fn(stage, self.checker.context)
            if result:
                self.checker.update_context(result)
                stage.output = result
        else:
            # Dry-run: just grant provided capabilities
            for prov_name in stage.provides:
                try:
                    cap = Capability[prov_name.upper()]
                    self.checker.grant(cap)
                    self.logs.append(f"[+] Granted: {prov_name}")
                except KeyError:
                    self.logs.append(f"[*] Custom capability: {prov_name}")

        return True

    def run(self,
            stage_runner: Optional[Callable] = None) -> PipelineResult:
        """Execute the full exploit chain.

        Args:
            stage_runner: Optional function(stage, context) -> result_dict
                         that runs each stage (e.g., in QEMU).

        Returns:
            PipelineResult with success/failure and capability summary.
        """
        for stage in self.stages:
            success = self.execute_stage(stage, stage_runner)
            if not success:
                return PipelineResult(
                    success=False,
                    final_stage=stage.name,
                    capabilities_achieved=[
                        c.name for c in self.checker.available
                    ],
                    capabilities_missing=stage.requires,
                    logs=self.logs,
                    error=f"Stage '{stage.name}' failed: {stage.requires}",
                )

        root_achieved = self.checker.has(Capability.ROOT_SHELL)

        return PipelineResult(
            success=True,
            final_stage=self.stages[-1].name if self.stages else "none",
            capabilities_achieved=[
                c.name for c in self.checker.available
            ],
            capabilities_missing=[],
            root_achieved=root_achieved,
            logs=self.logs,
        )

    def print_dependency_graph(self) -> str:
        """Generate a dependency graph of the chain."""
        lines = [f"Chain: {self.name}"]
        lines.append("=" * 60)
        for i, stage in enumerate(self.stages):
            cve = stage.cve_id or "builtin"
            lines.append(f"  [{i}] {stage.name} ({cve})")
            if stage.requires:
                lines.append(f"      ← requires: {', '.join(stage.requires)}")
            if stage.provides:
                lines.append(f"      → provides: {', '.join(stage.provides)}")
            if stage.output:
                lines.append(f"      → output:   {stage.output}")
        return "\n".join(lines)

    def find_missing_for_stage(self, stage_index: int) -> List[str]:
        """Find what capabilities are missing for a stage to execute."""
        if stage_index >= len(self.stages):
            return ["Stage index out of range"]

        stage = self.stages[stage_index]
        missing = []
        for req in stage.requires:
            try:
                cap = Capability[req.upper()]
                if not self.checker.has(cap):
                    missing.append(req)
            except KeyError:
                missing.append(f"{req} (unknown)")

        return missing


def demo_timerfd_chain():
    """Demonstrate the timerfd exploit chain analysis."""
    chain_config = {
        "name": "timerfd_full_chain_demo",
        "cves": [
            {
                "cve": "CVE-2026-XXXX",
                "role": "capability_provider",
                "stages": [
                    {
                        "name": "leak",
                        "method": "settimeofday_exploit",
                        "requires": [],
                        "provides": ["CAP_SYS_TIME", "CLOCK_WAS_SET"],
                    },
                ],
            },
            {
                "cve": "builtin",
                "role": "escalation",
                "escalation": "modprobe_path",
                "requires": ["KERNEL_CODE_EXEC", "MODPROBE_PATH_ADDR"],
            },
        ],
    }

    chain = ExploitChain(chain_config)
    print("=== Dependency Graph ===")
    print(chain.print_dependency_graph())

    # Validate
    valid, issues = chain.validate()
    print(f"\n=== Validation: {'PASS' if valid else 'FAIL'} ===")
    if issues:
        for issue in issues:
            print(f"  [!] {issue}")

    # Find what's missing for the primitive stage
    missing = chain.find_missing_for_stage(2)
    if missing:
        print(f"\n=== Missing for primitive stage ===")
        print(f"  Needs: {missing}")
        print(f"  Suggestion: Add a capability-provider CVE that grants {missing}")

    print("\n=== Capability Summary ===")
    print(chain.checker.summary())


if __name__ == "__main__":
    demo_timerfd_chain()
