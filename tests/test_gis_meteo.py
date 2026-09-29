"""Tests pour RTK-20 : OGC Anonymous Access."""
import uuid
from pathlib import Path
import responses
import pytest

from rtk.core.findings.store import FindingsStore
from rtk.modules.gis_meteo.ogc_anonymous_access import run

WMS_CAPABILITIES_XML = """<?xml version='1.0' encoding="UTF-8"?>
<WMS_Capabilities version="1.3.0">
  <Service><Name>WMS</Name></Service>
  <Capability>
    <Layer>
      <Name>public_roads</Name>
      <Title>Public Roads</Title>
    </Layer>
    <Layer>
      <Name>internal_admin_boundaries_confidential</Name>
      <Title>Internal Admin</Title>
    </Layer>
  </Capability>
</WMS_Capabilities>"""

@responses.activate
def test_ogc_anonymous_access_detects_sensitive_layer(tmp_path, scope, in_scope_target):
    db = tmp_path / "findings.sqlite"
    store = FindingsStore(db, encryption_key="test-key")
    mid = uuid.uuid4()
    
    # Mock de la réponse GetCapabilities
    responses.add(
        responses.GET,
        "http://mock-ogc-server.com/wms?service=WMS&request=GetCapabilities&version=1.3.0",
        body=WMS_CAPABILITIES_XML,
        status=200,
        content_type="application/xml"
    )
    
    findings = run(
        target=in_scope_target,
        scope=scope,
        store=store,
        mission_id=mid,
        ogc_endpoints=["http://mock-ogc-server.com/wms"]
    )
    
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == "high"
    assert "internal_admin_boundaries_confidential" in f.observed.raw_truncated
    assert f.defense_bypassed is True