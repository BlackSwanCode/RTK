"""Runner de corpus de tests pour le proxy MCP."""
from __future__ import annotations

import json
import uuid
from pathlib import Path

import httpx
import yaml

from rtk.core.findings.schema import AttackSpec, Finding, Observed, Target
from rtk.core.findings.store import FindingsStore
from rtk.core.judge.protocol import DeterministicJudge, Judge, TestCase
from rtk.core.logging import get_logger

log = get_logger("harness.corpus")


def load_corpus(corpus_dir: Path) -> list[TestCase]:
    cases = []
    for file_path in sorted(corpus_dir.glob("*.yaml")):
        data = yaml.safe_load(file_path.read_text())
        cases.append(TestCase(**data))
    return cases


async def run_case(
    case: TestCase,
    proxy_url: str,
    judge: Judge,
    store: FindingsStore,
    target: Target,
    mission_id: uuid.UUID,
) -> Finding | None:
    # Déduplication : vérifier si ce cas a déjà été testé pour cette cible
    existing = store.list(mission_id, filters={"module": "rtk.harness.corpus_runner"})
    if any(f.correlation.get("case_id") == case.id for f in existing):
        log.info("case_deduplicated", extra={"case_id": case.id})
        return None

    # Construction de la requête MCP
    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": case.tool_name, "arguments": json.loads(case.payload)}
    }

    try:
        async with httpx.AsyncClient() as client:
            resp = await client.post(f"{proxy_url}/message", json=payload, timeout=10.0)
            resp_data = resp.json()

            observed_response = ""
            if "result" in resp_data and "content" in resp_data["result"]:
                observed_response = " ".join(
                    c.get("text", "") for c in resp_data["result"]["content"] if c.get("type") == "text"
                )
            elif "error" in resp_data:
                observed_response = f"Error: {resp_data['error'].get('message', 'Unknown')}"

            verdict = judge.evaluate(case, observed_response)

            # Génération du Finding uniquement en cas de bypass ou échec critique
            if verdict.status in ("bypassed", "failed"):
                finding = Finding(
                    mission_id=mission_id,
                    module="rtk.harness.corpus_runner",
                    vector="LLM.T0001",
                    severity="high" if verdict.status == "bypassed" else "medium",
                    exploitability="confirmed",
                    atlas_technique="AML.T0051.001",
                    owasp_llm="LLM01",
                    target=target,
                    attack=AttackSpec(description=case.description, payload=case.payload),
                    observed=Observed(summary=f"Judge verdict: {verdict.status}. Response: {observed_response[:200]}"),
                    expected_defense="Model should refuse or sanitize the input according to safety guidelines.",
                    defense_bypassed=(verdict.status == "bypassed"),
                    correlation={"case_id": case.id},
                    simulated_attack=True,
                )
                store.add(finding)
                return finding

    except Exception as e:
        log.error("case_execution_failed", extra={"case_id": case.id, "error": str(e)})

    return None
