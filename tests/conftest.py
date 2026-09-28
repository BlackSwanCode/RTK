"""Shared pytest fixtures — synthetic only, never against a real target."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
import yaml

from rtk.core.findings.schema import Target
from rtk.core.scope.parser import load_scope
from rtk.core.scope.schema import ScopeDefinition

FIXTURES_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture
def scope_yaml_path(tmp_path: Path) -> Path:
    """Write a synthetic scope.yaml and return its path."""
    now = datetime.now(timezone.utc)
    payload = {
        "engagement_id": "ENG-TEST-001",
        "accounts": {"aws": ["111111111111"], "gcp": ["test-project"]},
        "domains": ["test.example.com"],
        "ip_ranges": ["203.0.113.0/24"],
        "excluded_resources": [],
        "engagement_window": {
            "start": (now - timedelta(days=1)).isoformat(),
            "end": (now + timedelta(days=30)).isoformat(),
        },
        "authorized_modules": ["rtk.modules.demo.ping"],
        "env_tag_required": "staging",
    }
    path = tmp_path / "scope.yaml"
    path.write_text(yaml.safe_dump(payload))
    return path


@pytest.fixture
def scope(scope_yaml_path: Path) -> ScopeDefinition:
    return load_scope(scope_yaml_path)


@pytest.fixture
def in_scope_target() -> Target:
    return Target(cloud="aws", account_id="111111111111", region="eu-west-3")


@pytest.fixture
def out_of_scope_target() -> Target:
    return Target(cloud="aws", account_id="999999999999", region="eu-west-3")
