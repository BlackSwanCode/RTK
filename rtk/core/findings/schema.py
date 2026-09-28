"""Pydantic schema for the RTK Findings Store (V1)."""
from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone
from typing import Literal
from uuid import UUID, uuid4

from pydantic import BaseModel, Field, model_validator


class Target(BaseModel):
    cloud: Literal["aws", "gcp"]
    account_id: str
    region: str | None = None
    resource_arn: str | None = None


class AttackSpec(BaseModel):
    description: str
    payload: str | None = None
    request: dict | None = None


class Observed(BaseModel):
    summary: str
    raw_truncated: str | None = Field(default=None, max_length=4096)
    raw_sha256: str | None = None

    @model_validator(mode="after")
    def _check_raw_consistency(self) -> "Observed":
        if self.raw_truncated is not None and self.raw_sha256 is None:
            self.raw_sha256 = hashlib.sha256(self.raw_truncated.encode("utf-8")).hexdigest()
        return self


class Finding(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    timestamp_utc: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    mission_id: UUID
    module: str
    vector: str
    severity: Literal["critical", "high", "medium", "low", "info"]
    exploitability: Literal["confirmed", "probable", "theoretical"]

    atlas_technique: str | None = None
    owasp_llm: str | None = None

    target: Target
    attack: AttackSpec
    observed: Observed
    expected_defense: str
    defense_bypassed: bool
    evidence_ref: str | None = None
    correlation: dict = Field(default_factory=dict)
    simulated_attack: bool = True
    mttd: timedelta | None = None
    chain_hash: str | None = None

    @model_validator(mode="after")
    def _coherence(self) -> "Finding":
        high_or_above = self.severity in {"critical", "high"}
        theoretical = self.exploitability == "theoretical"
        if high_or_above and theoretical and not self.observed.raw_sha256:
            raise ValueError("severity>=high + exploitability=theoretical requires observed.raw_sha256")
        if high_or_above and (not self.atlas_technique or not self.owasp_llm):
            raise ValueError("severity>=high requires both atlas_technique and owasp_llm")
        return self


class MCPCall(BaseModel):
    """Modèle de télémétrie pour les appels MCP transitant par le proxy.

    Séparé de `Finding` car la télémétrie de haut volume ne doit pas polluer
    la table des vulnérabilités, et ne possède pas de sévérité ou d'exploitabilité.
    """
    id: UUID = Field(default_factory=uuid4)
    timestamp_utc: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    mission_id: UUID
    session_id: str
    method: str  # ex: "tools/call", "resources/read"
    tool_name: str | None = None
    args_hash: str
    args_summary: str  # Tronqué à 200 caractères
    result_hash: str
    result_summary: str  # Tronqué à 200 caractères
    latency_ms: float
    success: bool
