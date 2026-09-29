# rtk/modules/iam/privesc_paths.py
from __future__ import annotations

import json
from uuid import UUID

import boto3

from rtk.core.findings.schema import AttackSpec, Finding, Observed, Target
from rtk.core.findings.store import FindingsStore
from rtk.core.logging import get_logger
from rtk.core.scope.parser import assert_in_scope
from rtk.core.scope.schema import ScopeDefinition

log = get_logger("modules.iam.privesc_paths")

def run(
    target: Target,
    scope: ScopeDefinition,
    store: FindingsStore,
    mission_id: UUID,
) -> list[Finding]:
    assert_in_scope(target, scope, module="rtk.modules.iam.privesc_paths")
    findings = []
    
    if target.cloud != "aws":
        log.info("skip_non_aws", extra={"cloud": target.cloud})
        return findings

    client = boto3.client("iam", region_name=target.region or "us-east-1")
    
    try:
        paginator = client.get_paginator("list_roles")
        for page in paginator.paginate():
            for role in page["Roles"]:
                trust_policy = json.loads(role["AssumeRolePolicyDocument"])
                statements = trust_policy.get("Statement", [])
                
                for stmt in statements:
                    if stmt.get("Effect") == "Allow" and "sts:AssumeRole" in stmt.get("Action", []):
                        principal = stmt.get("Principal", {})
                        # Détection de principal wildcard ou cross-account non restreint
                        if principal == "*":
                            _add_finding(findings, target, mission_id, role["RoleName"], "Wildcard Principal (*)")
                        elif "AWS" in principal:
                            aws_principals = principal["AWS"]
                            if isinstance(aws_principals, str):
                                aws_principals = [aws_principals]
                            for p in aws_principals:
                                if p == "*" or (isinstance(p, str) and not p.startswith(f"arn:aws:iam::{target.account_id}:")):
                                    _add_finding(findings, target, mission_id, role["RoleName"], f"Overly permissive cross-account trust: {p}")
    except Exception as e:
        log.error("iam_enumeration_failed", extra={"error": str(e)})

    return findings

def _add_finding(findings: list, target: Target, mission_id: UUID, role_name: str, reason: str):
    findings.append(Finding(
        mission_id=mission_id, module="rtk.modules.iam.privesc_paths", vector="06",
        severity="high", exploitability="probable", atlas_technique="AML.T0051.002", owasp_llm="LLM06",
        target=target, attack=AttackSpec(description="IAM Privilege Escalation Path", payload=role_name),
        observed=Observed(summary=reason),
        expected_defense="Trust policies must explicitly define allowed AWS accounts or services. No wildcards.",
        defense_bypassed=True, simulated_attack=False
    ))
