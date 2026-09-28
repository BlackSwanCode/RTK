"""Findings schema + store tests."""
import pytest

from rtk.core.findings.schema import (
    AttackSpec,
    Finding,
    Observed,
    Target,
)
from rtk.core.findings.store import FindingsStore


def _base_finding(**overrides):
    base = dict(
        module="rtk.test",
        vector="demo",
        severity="info",
        exploitability="confirmed",
        target=Target(cloud="aws", account_id="111111111111"),
        attack=AttackSpec(description="t"),
        observed=Observed(summary="s"),
        expected_defense="n/a",
        defense_bypassed=False,
    )
    base.update(overrides)
    return Finding(**base)


def test_finding_info_ok():
    f = _base_finding()
    assert f.severity == "info"


def test_finding_critical_theoretical_requires_sha256():
    with pytest.raises(Exception):
        _base_finding(
            severity="critical",
            exploitability="theoretical",
            observed=Observed(summary="s"),  # no raw_sha256
        )


def test_finding_high_requires_matrices():
    with pytest.raises(Exception):
        _base_finding(
            severity="high",
            exploitability="confirmed",
            # atlas_technique / owasp_llm left unset
        )


def test_store_roundtrip(tmp_path):
    db = tmp_path / "findings.sqlite"
    store = FindingsStore(db)
    f = _base_finding()
    store.add(f)
    assert len(store.list()) == 1
    assert store.list({"severity": "info"})[0].id == f.id
    assert store.list({"severity": "critical"}) == []

    out = store.export_json(tmp_path / "export.json")
    assert out.exists()
    assert b"rtk.test" in out.read_bytes()
