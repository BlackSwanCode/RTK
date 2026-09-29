# rtk/modules/llm_mcp/tool_poisoning_watch.py
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from uuid import UUID

import httpx

from rtk.core.findings.schema import AttackSpec, Finding, Observed, Target
from rtk.core.findings.store import FindingsStore
from rtk.core.logging import get_logger
from rtk.core.scope.parser import assert_in_scope
from rtk.core.scope.schema import ScopeDefinition

log = get_logger("modules.llm_mcp.tool_poisoning_watch")

def _hash_tool_schema(tool: dict) -> str:
    safe_tool = {k: v for k, v in tool.items() if k in ("name", "description", "inputSchema")}
    return hashlib.sha256(json.dumps(safe_tool, sort_keys=True).encode()).hexdigest()

def run(
    target: Target,
    scope: ScopeDefinition,
    store: FindingsStore,
    mission_id: UUID,
    mcp_endpoint: str,
    baseline_file: Path | None = None,
) -> list[Finding]:
    assert_in_scope(target, scope, module="rtk.modules.llm_mcp.tool_poisoning_watch")
    log.info("tool_watch_start", extra={"endpoint": mcp_endpoint})

    findings = []
    baseline_hashes = {}
    if baseline_file and baseline_file.exists():
        baseline_hashes = json.loads(baseline_file.read_text())

    payload = {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}
    try:
        resp = httpx.post(mcp_endpoint, json=payload, timeout=10.0)
        resp.raise_for_status()
        data = resp.json()
        
        tools = data.get("result", {}).get("tools", [])
        current_hashes = {t["name"]: _hash_tool_schema(t) for t in tools}

        for tool_name, current_hash in current_hashes.items():
            if baseline_file:
                if tool_name not in baseline_hashes:
                    findings.append(_make_finding(target, mission_id, tool_name, "new_tool", f"New tool detected: {tool_name}"))
                elif baseline_hashes[tool_name] != current_hash:
                    findings.append(_make_finding(target, mission_id, tool_name, "schema_modified", f"Schema changed for tool: {tool_name}"))
            else:
                # Mode découverte : on sauvegarde juste le baseline
                baseline_hashes[tool_name] = current_hash

        if baseline_file:
            # Vérifier les outils supprimés
            for tool_name in baseline_hashes:
                if tool_name not in current_hashes:
                    findings.append(_make_finding(target, mission_id, tool_name, "tool_removed", f"Tool removed: {tool_name}"))
        else:
            baseline_file.parent.mkdir(parents=True, exist_ok=True)
            baseline_file.write_text(json.dumps(baseline_hashes, indent=2))
            log.info("baseline_created", extra={"path": str(baseline_file)})

    except httpx.RequestError as e:
        log.error("tool_watch_failed", extra={"error": str(e)})
        
    log.info("tool_watch_complete", extra={"findings_count": len(findings)})
    return findings

def _make_finding(target: Target, mission_id: UUID, tool_name: str, vector_subtype: str, summary: str) -> Finding:
    return Finding(
        mission_id=mission_id, module="rtk.modules.llm_mcp.tool_poisoning_watch", vector="13",
        severity="high", exploitability="probable", atlas_technique="AML.T0055", owasp_llm="LLM07",
        target=target, attack=AttackSpec(description=f"Tool poisoning watch: {vector_subtype}", payload=tool_name),
        observed=Observed(summary=summary), expected_defense="Tool schemas must be versioned and changes must trigger alerts.",
        defense_bypassed=True, simulated_attack=False
    )
