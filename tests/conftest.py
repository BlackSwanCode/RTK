from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
import yaml

from rtk.core.findings.schema import Target
from rtk.core.scope.parser import load_scope
from rtk.core.scope.schema import ScopeDefinition


@pytest.fixture
def scope_yaml_path(tmp_path: Path) -> Path:
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
        "authorized_modules": ["rtk.modules.demo.ping", "rtk.modules.iam.wildcard_policies"],
        "env_tag_required": "staging",
    }
    path = tmp_path / "scope.yaml"
    path.write_text(yaml.safe_dump(payload))
    return path


@pytest.fixture
def scope(scope_yaml_path: Path):
    return load_scope(scope_yaml_path)


@pytest.fixture
def in_scope_target() -> Target:
    return Target(cloud="aws", account_id="111111111111", region="eu-west-3")


@pytest.fixture
def policies_dir(tmp_path: Path) -> Path:
    """5 policies: 3 safe, 2 risky (1 wildcard, 1 unrestricted PassRole)."""
    policies = [
        # Safe 1
        {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::my-bucket/*"}]},
        # Safe 2
        {"Version": "2012-10-17", "Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*"}]},
        # Safe 3
        {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "iam:PassRole", "Resource": "arn:aws:iam::111111111111:role/SpecificRole"}]},
        # Risky 1: Wildcard
        {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]},
        # Risky 2: Unrestricted PassRole
        {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "iam:PassRole", "Resource": "*"}]},
    ]
    for i, p in enumerate(policies):
        (tmp_path / f"policy_{i}.json").write_text(json.dumps(p))
    return tmp_path
