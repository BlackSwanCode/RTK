"""RTK-07: Detect overly permissive IAM policies (wildcards, unrestricted PassRole)."""
from __future__ import annotations

import json
from pathlib import Path
from uuid import UUID

from rtk.core.findings.schema import AttackSpec, Finding, Observed, Target
from rtk.core.findings.store import FindingsStore
from rtk.core.logging import get_logger
from rtk.core.scope.parser import assert_in_scope
from rtk.core.scope.schema import ScopeDefinition

log = get_logger("modules.iam.wildcard_policies")


def run(
    target: Target,
    scope: ScopeDefinition,
    store: FindingsStore,
    policies_dir: Path,
    mission_id: UUID,
) -> list[Finding]:
    """Analyze IAM policies for dangerous wildcards and unrestricted PassRole."""
    assert_in_scope(target, scope, module="rtk.modules.iam.wildcard_policies")
    log.info("scanning_policies", extra={"target": target.account_id, "policies_dir": str(policies_dir)})

    findings = []
    for p_file in Path(policies_dir).glob("*.json"):
        try:
            policy = json.loads(p_file.read_text())
        except json.JSONDecodeError:
            continue

        statements = policy.get("Statement", [])
        if isinstance(statements, dict):
            statements = [statements]

        is_risky = False
        reasons = []

        for stmt in statements:
            actions = stmt.get("Action", [])
            if isinstance(actions, str):
                actions = [actions]
            resources = stmt.get("Resource", [])
            if isinstance(resources, str):
                resources = [resources]

            has_wildcard_action = "*" in actions
            has_wildcard_resource = "*" in resources
            has_passrole = any("iam:passrole" in str(a).lower() for a in actions)
            passrole_unrestricted = has_passrole and (has_wildcard_resource or not resources)

            if has_wildcard_action and has_wildcard_resource:
                is_risky = True
                reasons.append("Wildcard Action and Resource")
            elif passrole_unrestricted:
                is_risky = True
                reasons.append("Unrestricted iam:PassRole")

        if is_risky:
            finding = Finding(
                mission_id=mission_id,
                module="rtk.modules.iam.wildcard_policies",
                vector="IAM.T0001",
                severity="high",
                exploitability="probable",
                atlas_technique="AML.T0051.001",
                owasp_llm="LLM06",
                target=target,
                attack=AttackSpec(description="Overly permissive IAM policy detected", payload=json.dumps(policy)),
                observed=Observed(summary=", ".join(reasons)),
                expected_defense="Apply principle of least privilege. Restrict Action and Resource to specific ARNs. Never allow iam:PassRole with wildcard resources.",
                defense_bypassed=True,
                simulated_attack=True,
            )
            store.add(finding)
            findings.append(finding)

    log.info("scan_complete", extra={"findings_count": len(findings)})
    return findings
