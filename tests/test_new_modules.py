"""Tests pour les nouveaux modules RTK-13, RTK-18, RTK-14, RTK-02, RTK-06."""
import json
import uuid
from pathlib import Path
from unittest.mock import patch, MagicMock
import pytest
import responses

from rtk.core.findings.store import FindingsStore
from rtk.modules.llm_mcp.tool_poisoning_watch import run as run_tool_watch
from rtk.modules.secrets.error_leakage import run as run_error_leakage

def test_tool_poisoning_watch_detects_change(tmp_path, scope, in_scope_target):
    db = tmp_path / "db.sqlite"
    store = FindingsStore(db, "test-key")
    mid = uuid.uuid4()
    
    baseline = {"safe_tool": "abc123hash"}
    baseline_file = tmp_path / "baseline.json"
    baseline_file.write_text(json.dumps(baseline))
    
    # Mock de la réponse MCP avec un outil modifié et un nouveau
    mock_response = {
        "jsonrpc": "2.0", "id": 1, "result": {
            "tools": [
                {"name": "safe_tool", "description": "modified desc", "inputSchema": {}}, # Hash changera
                {"name": "malicious_tool", "description": "bad", "inputSchema": {}} # Nouveau
            ]
        }
    }
    
    with patch("rtk.modules.llm_mcp.tool_poisoning_watch.httpx.post") as mock_post:
        mock_post.return_value.json.return_value = mock_response
        findings = run_tool_watch(
            target=in_scope_target, scope=scope, store=store, mission_id=mid,
            mcp_endpoint="http://fake/mcp", baseline_file=baseline_file
        )
        
    assert len(findings) == 2
    assert any("schema_modified" in f.attack.description for f in findings)
    assert any("new_tool" in f.attack.description for f in findings)

@responses.activate
def test_error_leakage_detects_arn(tmp_path, scope, in_scope_target):
    db = tmp_path / "db.sqlite"
    store = FindingsStore(db, "test-key")
    mid = uuid.uuid4()
    
    endpoint = "https://api.test.com/v1/data"
    responses.add(
        responses.POST, endpoint,
        body="Internal Server Error: Connection failed to arn:aws:s3:::secret-bucket",
        status=500
    )
    
    findings = run_error_leakage(
        target=in_scope_target, scope=scope, store=store, mission_id=mid,
        endpoints=[endpoint]
    )
    
    assert len(findings) == 1
    assert findings[0].severity == "high"
    assert "AWS ARN" in findings[0].observed.summary