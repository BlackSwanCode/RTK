"""Tests for RTK-04 Bucket Enumeration module (strictly mocked, no real network)."""
import uuid
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import yaml

from rtk.core.findings.store import FindingsStore
from rtk.modules.buckets.enum_buckets import run


@pytest.fixture
def conventions_yaml(tmp_path: Path) -> Path:
    data = {
        "conventions": [
            {"org": "acme", "envs": ["dev", "prod"], "suffixes": ["data", "logs"]}
        ]
    }
    path = tmp_path / "conventions.yaml"
    path.write_text(yaml.safe_dump(data))
    return path


def test_bucket_enum_mixed_access(tmp_path, scope, in_scope_target, conventions_yaml, mocker):
    """Test 1 public bucket and 1 private bucket."""
    db = tmp_path / "findings.sqlite"
    store = FindingsStore(db, encryption_key="test-key")
    mid = uuid.uuid4()

    # Mock boto3 pour AWS
    mock_boto3_client = mocker.patch("rtk.modules.buckets.enum_buckets.boto3.client")
    mock_s3 = MagicMock()
    mock_boto3_client.return_value = mock_s3

    # Scénario : acme-dev-data est PUBLIC, acme-prod-logs est PRIVÉ
    def list_objects_side_effect(Bucket, MaxKeys):
        if Bucket == "acme-dev-data":
            return {"Contents": [{"Key": "secret_dump.csv"}, {"Key": "config.json"}]}
        else:
            from botocore.exceptions import ClientError
            raise ClientError(
                {"Error": {"Code": "AccessDenied", "Message": "Access Denied"}},
                "ListObjectsV2"
            )

    mock_s3.list_objects_v2.side_effect = list_objects_side_effect

    # Mock requests pour GCP (non appelé ici car target.cloud="aws", mais bon à savoir)
    mock_requests = mocker.patch("rtk.modules.buckets.enum_buckets.requests.get")

    findings = run(
        target=in_scope_target, # cloud="aws"
        scope=scope,
        store=store,
        mission_id=mid,
        conventions_yaml=conventions_yaml,
    )

    # Vérifications
    assert len(findings) == 1
    finding = findings[0]
    assert finding.severity == "high"
    assert finding.target.account_id == "111111111111"
    assert "secret_dump.csv" in finding.observed.summary
    assert finding.atlas_technique is not None  # Contrainte V1 respectée

    # Vérifier que boto3 a bien été appelé avec la config UNSIGNED
    call_kwargs = mock_boto3_client.call_args[1]
    assert call_kwargs["config"].signature_version == "unsigned"
