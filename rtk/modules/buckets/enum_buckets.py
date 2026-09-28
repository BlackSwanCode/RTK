"""RTK-04: Enumerate and test anonymous read access to cloud storage buckets.

STRICTLY READ-ONLY: This module performs NO write operations. It only attempts
unsigned list_objects (AWS) or anonymous GET (GCP) to verify public exposure.
"""
from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any
from uuid import UUID

import boto3
import requests
import yaml
from botocore import UNSIGNED
from botocore.config import Config
from botocore.exceptions import ClientError

from rtk.core.findings.schema import AttackSpec, Finding, Observed, Target
from rtk.core.findings.store import FindingsStore
from rtk.core.logging import get_logger
from rtk.core.scope.parser import assert_in_scope
from rtk.core.scope.schema import ScopeDefinition

log = get_logger("modules.buckets.enum_buckets")

# Mapping for V1 schema constraints (severity >= high requires these)
ATLAS_TECHNIQUE = "AML.T0052.001"  # Cloud Storage Data Exposure
OWASP_LLM = "LLM06"  # Sensitive Information Disclosure


def _generate_bucket_names(conventions: list[dict[str, Any]]) -> list[str]:
    """Generate bucket names from YAML conventions."""
    names = []
    for conv in conventions:
        org = conv.get("org", "")
        envs = conv.get("envs", [])
        suffixes = conv.get("suffixes", [])
        for env in envs:
            for suffix in suffixes:
                names.append(f"{org}-{env}-{suffix}")
    return names


def _check_aws_bucket(bucket_name: str, region: str) -> tuple[bool, list[str]]:
    """Check AWS bucket anonymously. Returns (is_public, sample_keys)."""
    # Configuration EXPLICITE pour requêtes non signées (read-only)
    config = Config(signature_version=UNSIGNED, region_name=region or "us-east-1")
    s3 = boto3.client("s3", config=config)

    try:
        # MaxKeys=10 pour respecter la contrainte d'échantillonnage sans surcharger
        response = s3.list_objects_v2(Bucket=bucket_name, MaxKeys=10)
        keys = [obj["Key"] for obj in response.get("Contents", [])]
        return True, keys
    except ClientError as e:
        error_code = e.response.get("Error", {}).get("Code", "")
        if error_code in ("AccessDenied", "NoSuchBucket", "AllAccessDisabled"):
            return False, []
        log.warning("aws_unexpected_error", extra={"bucket": bucket_name, "error": error_code})
        return False, []


def _check_gcp_bucket(bucket_name: str) -> tuple[bool, list[str]]:
    """Check GCP bucket anonymously via direct HTTP GET. Returns (is_public, sample_keys)."""
    url = f"https://storage.googleapis.com/{bucket_name}?maxResults=10"
    try:
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            # Parse XML response pour extraire les clés
            root = ET.fromstring(response.content)
            ns = {"ns": "http://doc.s3.amazonaws.com/2006-03-01"}
            keys = [elem.text for elem in root.findall(".//ns:Key", ns)]
            return True, keys
        return False, []
    except requests.RequestException as e:
        log.warning("gcp_request_failed", extra={"bucket": bucket_name, "error": str(e)})
        return False, []


def run(
    target: Target,
    scope: ScopeDefinition,
    store: FindingsStore,
    mission_id: UUID,
    conventions_yaml: Path,
) -> list[Finding]:
    """Execute bucket enumeration based on naming conventions."""
    assert_in_scope(target, scope, module="rtk.modules.buckets.enum_buckets")
    log.info("bucket_enum_start", extra={"target": target.account_id, "conventions_file": str(conventions_yaml)})

    with open(conventions_yaml, "r") as f:
        conventions_data = yaml.safe_load(f)

    bucket_names = _generate_bucket_names(conventions_data.get("conventions", []))
    findings = []

    for bucket_name in bucket_names:
        is_public = False
        sample_keys: list[str] = []

        if target.cloud == "aws":
            is_public, sample_keys = _check_aws_bucket(bucket_name, target.region)
        elif target.cloud == "gcp":
            is_public, sample_keys = _check_gcp_bucket(bucket_name)

        if is_public:
            summary = f"Bucket is anonymously readable. Sample keys: {', '.join(sample_keys[:10])}"
            finding = Finding(
                mission_id=mission_id,
                module="rtk.modules.buckets.enum_buckets",
                vector="CLOUD.T0004",
                severity="high",  # Requires atlas/owasp per V1 schema
                exploitability="confirmed",
                atlas_technique=ATLAS_TECHNIQUE,
                owasp_llm=OWASP_LLM,
                target=target,
                attack=AttackSpec(
                    description="Anonymous read access verification",
                    payload=bucket_name,
                ),
                observed=Observed(summary=summary),
                expected_defense="Bucket policies must enforce 'Block Public Access' and require IAM authentication for all operations.",
                defense_bypassed=True,
                simulated_attack=False,  # Real infrastructure test
            )
            store.add(finding)
            findings.append(finding)
            log.info("public_bucket_found", extra={"bucket": bucket_name, "cloud": target.cloud})

    log.info("bucket_enum_complete", extra={"findings_count": len(findings)})
    return findings
