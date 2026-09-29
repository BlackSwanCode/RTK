"""RTK-20: Détection d'accès anonyme aux services OGC (WMS/WFS/WMTS).

Ce module interroge les endpoints OGC pour récupérer les GetCapabilities,
parse les couches exposées et flague celles contenant des mots-clés sensibles.
Strictement read-only et anonyme.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Literal
from uuid import UUID

import requests
from owslib.wms import WebMapService
from owslib.wfs import WebFeatureService
from pydantic import BaseModel

from rtk.core.findings.schema import AttackSpec, Finding, Observed, Target
from rtk.core.findings.store import FindingsStore
from rtk.core.logging import get_logger
from rtk.core.scope.parser import assert_in_scope
from rtk.core.scope.schema import ScopeDefinition

log = get_logger("modules.gis_meteo.ogc")

# Mots-clés indiquant une couche potentiellement sensible non destinée au public
SENSITIVE_LAYER_PATTERNS = [
    r"(?i)\b(internal|confidential|admin|privé|interne|restricted|secret)\b",
    r"(?i)\b(pii|rgpd|personnel|employee|salarié)\b",
    r"(?i)\b(critical_infra|réseau_eau|électricité|défense)\b",
]

class OGCService(BaseModel):
    url: str
    service_type: Literal["WMS", "WFS", "WMTS"]


def _check_ogc_capabilities(service: OGCService, timeout: int = 10) -> tuple[bool, list[str], str]:
    """Interroge le service OGC et extrait les noms de couches sensibles."""
    try:
        params = {"service": service.service_type, "request": "GetCapabilities", "version": "1.3.0" if service.service_type == "WMS" else "2.0.0"}
        resp = requests.get(service.url, params=params, timeout=timeout)
        resp.raise_for_status()
        
        layers = []
        if service.service_type == "WMS":
            wms = WebMapService(service.url, version="1.3.0", xml=resp.content)
            layers = list(wms.contents.keys())
        elif service.service_type == "WFS":
            wfs = WebFeatureService(service.url, version="2.0.0", xml=resp.content)
            layers = list(wfs.contents.keys())
            
        sensitive_layers = []
        for layer in layers:
            if any(re.search(pattern, layer) for pattern in SENSITIVE_LAYER_PATTERNS):
                sensitive_layers.append(layer)
                
        return True, sensitive_layers, f"Found {len(layers)} layers, {len(sensitive_layers)} flagged as sensitive."
        
    except requests.RequestException as e:
        log.warning("ogc_request_failed", extra={"url": service.url, "error": str(e)})
        return False, [], str(e)
    except Exception as e:
        log.warning("ogc_parse_failed", extra={"url": service.url, "error": str(e)})
        return False, [], str(e)


def run(
    target: Target,
    scope: ScopeDefinition,
    store: FindingsStore,
    mission_id: UUID,
    ogc_endpoints: list[str],
) -> list[Finding]:
    """Exécute le scan OGC sur une liste d'endpoints fournie."""
    assert_in_scope(target, scope, module="rtk.modules.gis_meteo.ogc_anonymous_access")
    log.info("ogc_scan_start", extra={"target": target.account_id, "endpoints_count": len(ogc_endpoints)})
    
    findings = []
    for url in ogc_endpoints:
        # Détection basique du type de service (peut être améliorée)
        svc_type = "WFS" if "wfs" in url.lower() else "WMS"
        service = OGCService(url=url, service_type=svc_type) # type: ignore
        
        is_accessible, sensitive_layers, summary = _check_ogc_capabilities(service)
        
        if is_accessible and sensitive_layers:
            finding = Finding(
                mission_id=mission_id,
                module="rtk.modules.gis_meteo.ogc_anonymous_access",
                vector="20",
                severity="high",
                exploitability="confirmed",
                atlas_technique="AML.T0052.001", # Data Exposure
                owasp_llm="LLM06", # Sensitive Info Disclosure (adapté au contexte data)
                target=target,
                attack=AttackSpec(
                    description="Anonymous GetCapabilities request",
                    payload=url,
                ),
                observed=Observed(
                    summary=summary,
                    raw_truncated=", ".join(sensitive_layers)[:4000]
                ),
                expected_defense="Les couches OGC sensibles doivent être protégées par authentification (ex: Basic Auth, OAuth2) ou retirées du service public.",
                defense_bypassed=True,
                simulated_attack=False,
            )
            store.add(finding)
            findings.append(finding)
            log.info("ogc_sensitive_layer_exposed", extra={"url": url, "layers": sensitive_layers})

    log.info("ogc_scan_complete", extra={"findings_count": len(findings)})
    return findings