import hashlib
import json
import uuid
import pytest

from rtk.core.findings.schema import AttackSpec, Finding, Observed, Target
from rtk.core.findings.store import FindingsStore


def _base_finding(mission_id: uuid.UUID, **overrides):
    base = dict(
        mission_id=mission_id,
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


def test_store_chain_hash_integrity(tmp_path):
    db = tmp_path / "findings.sqlite"
    store = FindingsStore(db, encryption_key="test-key")
    mid = uuid.uuid4()

    f1 = _base_finding(mission_id=mid, module="mod1")
    store.add(f1)

    f2 = _base_finding(mission_id=mid, module="mod2")
    store.add(f2)

    assert store.verify_chain(mid) is True

    # Falsification manuelle en base pour briser la chaîne
    with store._connect() as conn:
        conn.execute("UPDATE findings SET chain_hash = 'FALSIFIED' WHERE id = ?", (str(f1.id),))

    assert store.verify_chain(mid) is False
