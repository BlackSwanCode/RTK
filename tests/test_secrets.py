"""Tests pour RTK-01 : Multi-repo secrets scan."""
import uuid
from pathlib import Path
from unittest.mock import patch
import pytest

from rtk.core.findings.store import FindingsStore
from rtk.modules.secrets.multi_repo_scan import run

MOCK_GITLEAKS_OUTPUT = [
    {
        "RuleID": "aws-access-token",
        "File": "config.py",
        "StartLine": 12,
        "Commit": "abc123def456",
        "Secret": "AKIAIOSFODNN7EXAMPLE",
        "Fingerprint": "config.py:aws-access-token:12"
    }
]

@patch("rtk.modules.secrets.multi_repo_scan._run_gitleaks")
def test_secrets_multi_repo_scan_finds_historical_secret(mock_gitleaks, tmp_path, scope, in_scope_target):
    db = tmp_path / "findings.sqlite"
    store = FindingsStore(db, encryption_key="test-key")
    mid = uuid.uuid4()
    
    # Création d'un faux dépôt git
    repo_dir = tmp_path / "fake_repo"
    repo_dir.mkdir()
    (repo_dir / ".git").mkdir()
    
    mock_gitleaks.return_value = MOCK_GITLEAKS_OUTPUT
    
    findings = run(
        target=in_scope_target,
        scope=scope,
        store=store,
        mission_id=mid,
        repos_dir=tmp_path
    )
    
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == "critical" # AWS token détecté
    assert f.correlation["repo"] == "fake_repo"
    assert f.correlation["commit"] == "abc123def456"
    assert "[REDACTED]" in f.observed.raw_truncated # Vérification du masquage