"""Demo module: emit a single ``info`` finding to validate the pipeline."""
from __future__ import annotations

from rtk.core.findings.schema import (
    AttackSpec,
    Finding,
    Observed,
    Target,
)
from rtk.core.findings.store import FindingsStore
from rtk.core.logging import get_logger
from rtk.core.scope.parser import assert_in_scope
from rtk.core.scope.schema import ScopeDefinition

log = get_logger("modules.demo.ping")


def run(
    target: Target,
    scope: ScopeDefinition,
    store: FindingsStore,
) -> Finding:
    """Validate scope then emit a synthetic ``info`` finding.

    This module performs NO network I/O. It exists solely to prove that
    the scope → module → store → export chain is wired end-to-end.
    """
    assert_in_scope(target, scope, module="rtk.modules.demo.ping")
    log.info(
        "demo_ping_executed",
        extra={"target": target.model_dump(), "scope": scope.engagement_id},
    )
    finding = Finding(
        module="rtk.modules.demo.ping",
        vector="demo",
        severity="info",
        exploitability="confirmed",
        target=target,
        attack=AttackSpec(description="synthetic connectivity probe (no I/O)"),
        observed=Observed(summary="scope validated, finding emitted"),
        expected_defense="n/a — demo module",
        defense_bypassed=False,
        simulated_attack=True,
    )
    store.add(finding)
    return finding
