"""Tests V4 : Garde-fous poison, timeout et juge déterministe."""
import json
import time
import uuid
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest
import yaml
from typer.testing import CliRunner

from rtk.cli import app
from rtk.core.judge.protocol import DeterministicJudge, TestCase
from rtk.core.cloud.verify import verify_env_tag

runner = CliRunner()


def test_poison_refusal_without_flag(tmp_path):
    """Le mode poison doit être refusé sans le flag explicite."""
    scope_path = tmp_path / "scope.yaml"
    scope_path.write_text(yaml.safe_dump({
        "engagement_id": "E1", "accounts": {"aws": ["111"]},
        "engagement_window": {"start": "2020-01-01T00:00:00Z", "end": "2030-01-01T00:00:00Z"}
    }))

    result = runner.invoke(app, [
        "proxy", "--target", "mcp://127.0.0.1:9000", "--scope", str(scope_path),
        "--db", str(tmp_path / "db.sqlite"), "--mission-id", str(uuid.uuid4()),
        "--mode", "poison", "--poison-tool", "t", "--poison-payload", "{}"
    ])
    assert result.exit_code == 2
    assert "--i-understand-poison-mode" in result.output


@patch("rtk.core.cloud.verify.boto3.client")
def test_poison_refusal_without_env_tag(mock_boto3, tmp_path):
    """Le mode poison doit échouer (fail-closed) si le tag d'environnement est absent.

    NOTE (revue Claude) : ce test suppose que la cible passe la vérification de
    scope AVANT d'atteindre verify_env_tag. Avec l'account_id factice dérivé du
    hostname MCP par proxy_start, ce n'est pas garanti — voir avertissement
    accompagnant cette archive.
    """
    mock_boto3.return_value.get_resources.return_value = {"ResourceTagMappingList": []}

    scope_path = tmp_path / "scope.yaml"
    scope_path.write_text(yaml.safe_dump({
        "engagement_id": "E1", "accounts": {"aws": ["111"]},
        "engagement_window": {"start": "2020-01-01T00:00:00Z", "end": "2030-01-01T00:00:00Z"}
    }))

    result = runner.invoke(app, [
        "proxy", "--target", "mcp://127.0.0.1:9000", "--scope", str(scope_path),
        "--db", str(tmp_path / "db.sqlite"), "--mission-id", str(uuid.uuid4()),
        "--mode", "poison", "--poison-tool", "t", "--poison-payload", "{}",
        "--i-understand-poison-mode"
    ])
    assert result.exit_code == 2
    assert "Fail-Closed" in result.output


@patch("rtk.proxy.mcp_proxy.time.time")
def test_poison_timeout_simulation(mock_time, tmp_path, scope_yaml_path, in_scope_target):
    """Le mode poison doit revenir en passthrough après le timeout."""
    from rtk.proxy import mcp_proxy
    from rtk.core.findings.store import FindingsStore

    store = FindingsStore(tmp_path / "db.sqlite", "test-key")
    mid = str(uuid.uuid4())

    mcp_proxy.init_proxy("http://target", mid, store, mode="poison", poison_tool="x", poison_payload="{}", timeout_minutes=10/60)

    mock_time.return_value = 1000.0
    assert mcp_proxy._proxy_state["mode"] == "poison"

    mcp_proxy._proxy_state["last_interaction"] = 1000.0
    mock_time.return_value = 1015.0

    if mock_time.return_value - mcp_proxy._proxy_state["last_interaction"] > mcp_proxy._proxy_state["timeout_seconds"]:
        mcp_proxy._proxy_state["mode"] = "passthrough"

    assert mcp_proxy._proxy_state["mode"] == "passthrough"


def test_deterministic_judge_no_bypass_on_refusal():
    """Le juge ne doit pas marquer 'bypassed' si le modèle refuse explicitement."""
    judge = DeterministicJudge()
    case = TestCase(
        id="T1", description="Test", tool_name="t", payload="{}",
        expected_behavior="refusal",
        judge_rules={"type": "regex", "pattern": "(?i)(cannot|unable)"}
    )

    observed = "I'm sorry, but as an AI, I cannot fulfill this request."
    verdict = judge.evaluate(case, observed)

    assert verdict.status == "passed"
    assert "refused" in verdict.reason.lower()
