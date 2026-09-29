"""Tests pour RTK-08 : Cartographie surface externe."""
import uuid
from unittest.mock import patch, MagicMock
import pytest

from rtk.core.findings.store import FindingsStore
from rtk.modules.network.external_surface import run


def test_mcp_endpoint_detected(tmp_path, scope, in_scope_target):
    """Test qu'un endpoint MCP exposé est détecté."""
    db = tmp_path / "db.sqlite"
    store = FindingsStore(db, "test-key")
    mid = uuid.uuid4()

    # Mock subfinder
    with patch("rtk.modules.network.external_surface._enumerate_subdomains") as mock_enum:
        mock_enum.return_value = ["mcp-dev.example.com"]

        # Mock probe MCP
        with patch("rtk.modules.network.external_surface._probe_endpoint") as mock_probe:
            mock_probe.return_value = {
                "url": "https://mcp-dev.example.com",
                "service_type": "MCP",
                "confidence": 0.9,
                "status_code": 200,
                "headers": {"mcp-protocol-version": "2024-11-05"}
            }

            findings = run(
                target=in_scope_target,
                scope=scope,
                store=store,
                mission_id=mid,
                domains=["example.com"]
            )

    assert len(findings) == 1
    assert findings[0].severity == "high"
    assert "MCP" in findings[0].observed.summary


def test_wms_endpoint_detected(tmp_path, scope, in_scope_target):
    """Test qu'un endpoint WMS exposé est détecté."""
    db = tmp_path / "db.sqlite"
    store = FindingsStore(db, "test-key")
    mid = uuid.uuid4()

    with patch("rtk.modules.network.external_surface._enumerate_subdomains") as mock_enum:
        mock_enum.return_value = ["wms.example.com"]

        with patch("rtk.modules.network.external_surface._probe_endpoint") as mock_probe:
            mock_probe.return_value = {
                "url": "https://wms.example.com",
                "service_type": "WMS",
                "confidence": 0.85,
                "status_code": 200,
                "headers": {}
            }

            findings = run(
                target=in_scope_target,
                scope=scope,
                store=store,
                mission_id=mid,
                domains=["example.com"]
            )

    assert len(findings) == 1
    assert findings[0].severity == "medium"  # WMS = medium
    assert "WMS" in findings[0].observed.summary
