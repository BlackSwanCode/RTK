from __future__ import annotations

import uuid
from rtk.core.findings.schema import AttackSpec, Finding, Observed, Target
from rtk.core.findings.store import FindingsStore
from rtk.core.logging import get_logger
from rtk.core.scope.parser import assert_in_scope
from rtk.core.scope.schema import ScopeDefinition

log = get_logger("modules.demo.ping")


def run(
    target: Target,
    scope: ScopeDefinition,
    store: FindingsStore,
    mission_id: uuid.UUID,
) -> Finding:
    assert_in_scope(target, scope, module="rtk.modules.demo.ping")
    log.info("demo_ping_executed", extra={"target": target.model_dump(), "scope": scope.engagement_id})

    finding = Finding(
        mission_id=mission_id,
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
