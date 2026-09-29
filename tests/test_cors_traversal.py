"""Tests pour RTK-05 : CORS & traversée de préfixe."""
import uuid
from unittest.mock import patch, MagicMock
import pytest

from rtk.core.findings.store import FindingsStore
from rtk.modules.buckets.cors_traversal import run


def test_cors_vulnerability_detected(tmp_path, scope, in_scope_target):
    """Test qu'une config CORS permissive est détectée."""
    db = tmp_path / "db.sqlite"
    store = FindingsStore(db, "test-key")
    mid = uuid.uuid4()

    buckets = [
        {
            "name": "test-bucket",
            "cloud": "aws",
            "region": "us-east-1",
            "url": "https://test-bucket.s3.amazonaws.com"
        }
    ]

    # Mock de la réponse CORS vulnérable
    with patch("rtk.modules.buckets.cors_traversal.httpx.options") as mock_options:
        mock_resp = MagicMock()
        mock_resp.headers = {
            "Access-Control-Allow-Origin": "https://evil.example.com",
            "Access-Control-Allow-Credentials": "true"
        }
        mock_options.return_value = mock_resp

        # Mock de la traversée (non vulnérable ici)
        with patch("rtk.modules.buckets.cors_traversal.httpx.get") as mock_get:
            mock_get.return_value.status_code = 403

            findings = run(
                target=in_scope_target,
                scope=scope,
                store=store,
                mission_id=mid,
                buckets=buckets
            )

    assert len(findings) == 1
    assert findings[0].severity == "high"
    assert "CORS" in findings[0].observed.summary


def test_path_traversal_detected(tmp_path, scope, in_scope_target):
    """Test qu'une traversée de préfixe est détectée."""
    db = tmp_path / "db.sqlite"
    store = FindingsStore(db, "test-key")
    mid = uuid.uuid4()

    buckets = [
        {
            "name": "tiles-service",
            "cloud": "gcp",
            "url": "https://storage.googleapis.com/tiles-service"
        }
    ]

    # Mock CORS non vulnérable
    with patch("rtk.modules.buckets.cors_traversal.httpx.options") as mock_options:
        mock_options.return_value.headers = {}

        # Mock traversée vulnérable
        with patch("rtk.modules.buckets.cors_traversal.httpx.get") as mock_get:
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.content = b"secret data content"
            mock_resp.text = "secret data content"
            mock_get.return_value = mock_resp

            findings = run(
                target=in_scope_target,
                scope=scope,
                store=store,
                mission_id=mid,
                buckets=buckets
            )

    assert len(findings) == 1
    assert findings[0].severity == "critical"
    assert "traversal" in findings[0].attack.description.lower()
