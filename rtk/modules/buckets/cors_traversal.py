"""RTK-05: Test CORS et traversée de préfixe sur buckets cloud.

Détecte les configurations CORS trop permissives et les vulnérabilités
de traversée de chemin sur les services de tuiles/objets.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Literal
from uuid import UUID

import httpx
from pydantic import BaseModel

from rtk.core.findings.schema import AttackSpec, Finding, Observed, Target
from rtk.core.findings.store import FindingsStore
from rtk.core.logging import get_logger
from rtk.core.scope.parser import assert_in_scope
from rtk.core.scope.schema import ScopeDefinition

log = get_logger("modules.buckets.cors_traversal")


class BucketInfo(BaseModel):
    name: str
    cloud: Literal["aws", "gcp", "azure"]
    region: str | None = None
    url: str


def _test_cors(bucket: BucketInfo, test_origin: str = "https://evil.example.com") -> tuple[bool, dict]:
    """Teste si le bucket accepte des origines arbitraires via CORS."""
    headers = {
        "Origin": test_origin,
        "Access-Control-Request-Method": "GET",
    }

    try:
        # Requête OPTIONS pour vérifier CORS
        resp = httpx.options(bucket.url, headers=headers, timeout=10.0)

        allow_origin = resp.headers.get("Access-Control-Allow-Origin", "")
        allow_credentials = resp.headers.get("Access-Control-Allow-Credentials", "")

        # Vulnérabilité si l'origine arbitraire est reflétée avec credentials
        if allow_origin == test_origin or allow_origin == "*":
            if allow_credentials.lower() == "true":
                return True, {
                    "allow_origin": allow_origin,
                    "allow_credentials": allow_credentials,
                    "test_origin": test_origin
                }
        return False, {}

    except httpx.RequestError as e:
        log.warning("cors_test_failed", extra={"bucket": bucket.name, "error": str(e)})
        return False, {}


def _test_path_traversal(bucket: BucketInfo) -> tuple[bool, str]:
    """Teste la traversée de préfixe sur les services de tuiles/objets."""
    # Payloads de traversée courants
    traversal_payloads = [
        "../secret.txt",
        "../../etc/passwd",
        "..%2f..%2fetc%2fpasswd",
        "?prefix=../",
        "?prefix=../../secret",
    ]

    for payload in traversal_payloads:
        test_url = f"{bucket.url.rstrip('/')}/{payload}"
        try:
            resp = httpx.get(test_url, timeout=10.0)
            # Si on obtient une réponse 200 avec du contenu, c'est suspect
            if resp.status_code == 200 and len(resp.content) > 0:
                # Vérifier que ce n'est pas juste une page d'erreur XML/JSON
                if not any(marker in resp.text.lower() for marker in ["accessdenied", "nosuchkey", "error"]):
                    return True, payload
        except httpx.RequestError:
            continue

    return False, ""


def run(
    target: Target,
    scope: ScopeDefinition,
    store: FindingsStore,
    mission_id: UUID,
    buckets: list[dict],  # Liste de BucketInfo en dict
) -> list[Finding]:
    """Exécute les tests CORS et traversée sur une liste de buckets."""
    assert_in_scope(target, scope, module="rtk.modules.buckets.cors_traversal")
    log.info("cors_traversal_start", extra={"buckets_count": len(buckets)})

    findings = []

    for bucket_dict in buckets:
        bucket = BucketInfo(**bucket_dict)

        # Test CORS
        cors_vulnerable, cors_details = _test_cors(bucket)
        if cors_vulnerable:
            finding = Finding(
                mission_id=mission_id,
                module="rtk.modules.buckets.cors_traversal",
                vector="05",
                severity="high",
                exploitability="probable",
                atlas_technique="AML.T0052.002",  # CORS Misconfiguration
                owasp_llm="LLM06",
                target=target,
                attack=AttackSpec(
                    description="CORS misconfiguration allows arbitrary origin",
                    payload=bucket.url,
                ),
                observed=Observed(
                    summary=f"CORS accepts origin {cors_details['test_origin']} with credentials",
                    raw_truncated=str(cors_details)
                ),
                expected_defense="CORS must restrict Access-Control-Allow-Origin to trusted domains only. Never use wildcard with credentials.",
                defense_bypassed=True,
                simulated_attack=False,
            )
            store.add(finding)
            findings.append(finding)
            log.info("cors_vulnerability_found", extra={"bucket": bucket.name})

        # Test traversée de préfixe
        traversal_vulnerable, traversal_payload = _test_path_traversal(bucket)
        if traversal_vulnerable:
            finding = Finding(
                mission_id=mission_id,
                module="rtk.modules.buckets.cors_traversal",
                vector="05",
                severity="critical",
                exploitability="confirmed",
                atlas_technique="AML.T0052.003",  # Path Traversal
                owasp_llm="LLM06",
                target=target,
                attack=AttackSpec(
                    description="Path traversal allows access to objects outside prefix",
                    payload=traversal_payload,
                ),
                observed=Observed(
                    summary=f"Successfully accessed out-of-prefix object via {traversal_payload}",
                ),
                expected_defense="Object storage services must validate and sanitize path parameters. No directory traversal allowed.",
                defense_bypassed=True,
                simulated_attack=False,
            )
            store.add(finding)
            findings.append(finding)
            log.info("traversal_vulnerability_found", extra={"bucket": bucket.name, "payload": traversal_payload})

    log.info("cors_traversal_complete", extra={"findings_count": len(findings)})
    return findings
