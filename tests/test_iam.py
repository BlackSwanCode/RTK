import uuid
from rtk.core.findings.store import FindingsStore
from rtk.modules.iam.wildcard_policies import run


def test_wildcard_policies_module(tmp_path, scope, in_scope_target):
    db = tmp_path / "findings.sqlite"
    store = FindingsStore(db, encryption_key="test-key")
    mid = uuid.uuid4()

    # Le fixture policies_dir contient 5 policies (3 sûres, 2 à risque)
    findings = run(
        target=in_scope_target,
        scope=scope,
        store=store,
        policies_dir=tmp_path,
        mission_id=mid
    )

    assert len(findings) == 2
    assert all(f.severity == "high" for f in findings)
    assert any("Unrestricted iam:PassRole" in f.observed.summary for f in findings)
    assert any("Wildcard Action and Resource" in f.observed.summary for f in findings)

    # Vérification que le store a bien enregistré les findings
    stored = store.list(mission_id=mid)
    assert len(stored) == 2
