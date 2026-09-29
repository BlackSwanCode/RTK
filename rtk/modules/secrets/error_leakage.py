# rtk/modules/secrets/error_leakage.py
from __future__ import annotations

import re
from uuid import UUID

import httpx

from rtk.core.findings.schema import AttackSpec, Finding, Observed, Target
from rtk.core.findings.store import FindingsStore
from rtk.core.logging import get_logger
from rtk.core.scope.parser import assert_in_scope
from rtk.core.scope.schema import ScopeDefinition

log = get_logger("modules.secrets.error_leakage")

# Patterns de secrets courants dans les stack traces
SECRET_PATTERNS = [
    (r"arn:aws:[a-z0-9-]+:[a-z0-9-]*:\d{12}:.+", "AWS ARN"),
    (r"AIza[0-9A-Za-z\-_]{35}", "GCP API Key"),
    (r"AKIA[0-9A-Z]{16}", "AWS Access Key"),
    (r"(?i)(password|secret|token)\s*[:=]\s*['\"][^'\"]{8,}['\"]", "Generic Secret"),
    (r"/etc/secrets/|/var/run/secrets/", "Secret File Path")
]

FUZZ_PAYLOADS = [
    {"json": {"invalid": "type"}},
    {"params": {"id": "1' OR '1'='1"}},
    {"headers": {"X-Forwarded-For": "localhost"}},
    {"data": "A" * 50000} # Payload oversized
]

def run(
    target: Target,
    scope: ScopeDefinition,
    store: FindingsStore,
    mission_id: UUID,
    endpoints: list[str],
) -> list[Finding]:
    assert_in_scope(target, scope, module="rtk.modules.secrets.error_leakage")
    findings = []

    for endpoint in endpoints:
        for i, fuzz in enumerate(FUZZ_PAYLOADS):
            try:
                resp = httpx.post(endpoint, timeout=5.0, **fuzz)
                if resp.status_code >= 500:
                    for pattern, secret_type in SECRET_PATTERNS:
                        matches = re.findall(pattern, resp.text)
                        if matches:
                            finding = Finding(
                                mission_id=mission_id, module="rtk.modules.secrets.error_leakage", vector="02",
                                severity="high", exploitability="probable", atlas_technique="AML.T0051.000", owasp_llm="LLM06",
                                target=target, attack=AttackSpec(description=f"Error leakage via fuzzing", payload=str(fuzz)),
                                observed=Observed(summary=f"Leaked {secret_type} in 500 response", raw_truncated=matches[0][:100]),
                                expected_defense="Generic error pages must be served in production. No stack traces or config paths.",
                                defense_bypassed=True, simulated_attack=False
                            )
                            store.add(finding)
                            findings.append(finding)
                            break # Un finding par endpoint pour éviter le spam
            except httpx.RequestError:
                continue

    return findings
