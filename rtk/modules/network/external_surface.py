"""RTK-08: Cartographie de la surface externe exposée.

Détecte les endpoints oubliés (MCP, LLM, WMS) via énumération de sous-domaines
et fingerprinting de services.
"""
from __future__ import annotations

import json
import subprocess
from pathlib import Path
from uuid import UUID

import httpx

from rtk.core.findings.schema import AttackSpec, Finding, Observed, Target
from rtk.core.findings.store import FindingsStore
from rtk.core.logging import get_logger
from rtk.core.scope.parser import assert_in_scope
from rtk.core.scope.schema import ScopeDefinition

log = get_logger("modules.network.external_surface")

# Signatures de fingerprinting
MCP_SIGNATURES = [
    lambda r: "jsonrpc" in r.text.lower() and "2.0" in r.text,
    lambda r: "mcp-protocol-version" in r.headers,
    lambda r: "/mcp" in r.url.path or "/sse" in r.url.path,
]

LLM_SIGNATURES = [
    lambda r: "openai" in r.text.lower() or "model" in r.text.lower(),
    lambda r: any(h in r.headers for h in ["x-ratelimit-remaining-tokens", "x-openai-organization"]),
]

WMS_SIGNATURES = [
    lambda r: "wms" in r.text.lower() and "getcapabilities" in r.text.lower(),
    lambda r: "service=\"wms\"" in r.text.lower(),
]


def _enumerate_subdomains(domain: str) -> list[str]:
    """Énumère les sous-domaines via subfinder (si disponible)."""
    try:
        result = subprocess.run(
            ["subfinder", "-d", domain, "-silent", "-json"],
            capture_output=True,
            text=True,
            timeout=60
        )
        if result.returncode == 0:
            subdomains = []
            for line in result.stdout.strip().split("\n"):
                if line:
                    try:
                        data = json.loads(line)
                        subdomains.append(data.get("host", ""))
                    except json.JSONDecodeError:
                        subdomains.append(line)
            return [s for s in subdomains if s]
    except (subprocess.SubprocessError, FileNotFoundError):
        log.warning("subfinder_not_available", extra={"domain": domain})
    return []


def _probe_endpoint(url: str) -> dict | None:
    """Probe un endpoint et retourne ses caractéristiques si intéressant."""
    try:
        resp = httpx.get(url, timeout=5.0, follow_redirects=True)

        service_type = None
        confidence = 0

        # Vérification MCP
        if any(sig(resp) for sig in MCP_SIGNATURES):
            service_type = "MCP"
            confidence = 0.9

        # Vérification LLM
        elif any(sig(resp) for sig in LLM_SIGNATURES):
            service_type = "LLM_API"
            confidence = 0.8

        # Vérification WMS
        elif any(sig(resp) for sig in WMS_SIGNATURES):
            service_type = "WMS"
            confidence = 0.85

        if service_type:
            return {
                "url": url,
                "service_type": service_type,
                "confidence": confidence,
                "status_code": resp.status_code,
                "headers": dict(resp.headers)
            }
    except httpx.RequestError:
        pass

    return None


def run(
    target: Target,
    scope: ScopeDefinition,
    store: FindingsStore,
    mission_id: UUID,
    domains: list[str],
) -> list[Finding]:
    """Cartographie la surface externe pour les domaines fournis."""
    assert_in_scope(target, scope, module="rtk.modules.network.external_surface")
    log.info("external_surface_start", extra={"domains": domains})

    findings = []
    all_endpoints = []

    # Énumération des sous-domaines
    for domain in domains:
        subdomains = _enumerate_subdomains(domain)
        all_endpoints.extend([f"https://{sub}" for sub in subdomains])
        all_endpoints.append(f"https://{domain}")

    log.info("subdomains_enumerated", extra={"count": len(all_endpoints)})

    # Fingerprinting de chaque endpoint
    for endpoint in all_endpoints:
        result = _probe_endpoint(endpoint)
        if result:
            finding = Finding(
                mission_id=mission_id,
                module="rtk.modules.network.external_surface",
                vector="08",
                severity="medium" if result["service_type"] == "WMS" else "high",
                exploitability="confirmed",
                atlas_technique="AML.T0056",  # Reconnaissance
                owasp_llm="LLM06",
                target=target,
                attack=AttackSpec(
                    description=f"Exposed {result['service_type']} endpoint detected",
                    payload=endpoint,
                ),
                observed=Observed(
                    summary=f"{result['service_type']} service found with confidence {result['confidence']:.0%}",
                    raw_truncated=json.dumps(result, indent=2)[:4000]
                ),
                expected_defense="Internal services (MCP, LLM APIs) should not be publicly exposed. Use private endpoints or VPN.",
                defense_bypassed=True,
                simulated_attack=False,
                correlation={"service_type": result["service_type"]}
            )
            store.add(finding)
            findings.append(finding)
            log.info("service_detected", extra={"url": endpoint, "type": result["service_type"]})

    log.info("external_surface_complete", extra={"findings_count": len(findings)})
    return findings
