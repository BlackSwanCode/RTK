"""Tests for minimal HTML reporting."""
import uuid
from pathlib import Path

from rtk.core.findings.schema import AttackSpec, Finding, Observed, Target
from rtk.core.findings.store import FindingsStore
from rtk.reporting.minimal_report import generate_report


def test_report_generation_and_sorting(tmp_path):
    db = tmp_path / "findings.sqlite"
    store = FindingsStore(db, encryption_key="test-key")
    mid = uuid.uuid4()

    target = Target(cloud="aws", account_id="111111111111")

    # Création de findings de sévérités différentes
    f1 = Finding(
        mission_id=mid, module="test", vector="v1", severity="info", exploitability="confirmed",
        target=target, attack=AttackSpec(description="t"), observed=Observed(summary="Info finding"),
        expected_defense="n/a", defense_bypassed=False
    )
    f2 = Finding(
        mission_id=mid, module="test", vector="v2", severity="critical", exploitability="confirmed",
        target=target, attack=AttackSpec(description="t"), observed=Observed(summary="Critical finding"),
        expected_defense="n/a", defense_bypassed=False, atlas_technique="T1", owasp_llm="L1"
    )
    f3 = Finding(
        mission_id=mid, module="test", vector="v3", severity="high", exploitability="confirmed",
        target=target, attack=AttackSpec(description="t"), observed=Observed(summary="High finding"),
        expected_defense="n/a", defense_bypassed=False, atlas_technique="T1", owasp_llm="L1"
    )

    # Ajout dans un ordre désordonné pour tester le tri
    store.add(f1)
    store.add(f3)
    store.add(f2)

    output_path = tmp_path / "rapport.html"
    generate_report(store, mid, output_path)

    html_content = output_path.read_text(encoding="utf-8")

    # Vérification du contenu et de l'ordre d'apparition (Critical doit apparaître avant High, avant Info)
    pos_critical = html_content.find("Critical finding")
    pos_high = html_content.find("High finding")
    pos_info = html_content.find("Info finding")

    assert pos_critical != -1
    assert pos_high != -1
    assert pos_info != -1

    # L'ordre dans le HTML doit respecter la sévérité décroissante
    assert pos_critical < pos_high < pos_info
    assert "severity-critical" in html_content
    assert "severity-high" in html_content
    assert "severity-info" in html_content
