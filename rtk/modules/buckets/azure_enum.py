"""RTK-04 (Azure): Énumération de containers Azure Blob Storage."""
from __future__ import annotations

from uuid import UUID

from rtk.core.cloud.azure import list_azure_containers, check_azure_container_public_access
from rtk.core.findings.schema import AttackSpec, Finding, Observed, Target
from rtk.core.findings.store import FindingsStore
from rtk.core.logging import get_logger
from rtk.core.scope.parser import assert_in_scope
from rtk.core.scope.schema import ScopeDefinition

log = get_logger("modules.buckets.azure_enum")


def run(
    target: Target,
    scope: ScopeDefinition,
    store: FindingsStore,
    mission_id: UUID,
    storage_accounts: list[str],
) -> list[Finding]:
    """Énumère les containers Azure et teste l'accès anonyme."""
    assert_in_scope(target, scope, module="rtk.modules.buckets.azure_enum")
    log.info("azure_enum_start", extra={"accounts": storage_accounts})

    findings = []

    for account in storage_accounts:
        containers = list_azure_containers(account)
        log.info("containers_listed", extra={"account": account, "count": len(containers)})

        for container in containers:
            container_url = f"https://{account}.blob.core.windows.net/{container}"
            if check_azure_container_public_access(container_url):
                finding = Finding(
                    mission_id=mission_id,
                    module="rtk.modules.buckets.azure_enum",
                    vector="04",
                    severity="high",
                    exploitability="confirmed",
                    atlas_technique="AML.T0052.001",
                    owasp_llm="LLM06",
                    target=target,
                    attack=AttackSpec(
                        description="Azure container accessible anonymously",
                        payload=container_url,
                    ),
                    observed=Observed(summary=f"Container {container} is publicly accessible"),
                    expected_defense="Disable anonymous public access on Azure Blob containers unless explicitly required.",
                    defense_bypassed=True,
                    simulated_attack=False,
                )
                store.add(finding)
                findings.append(finding)

    return findings
