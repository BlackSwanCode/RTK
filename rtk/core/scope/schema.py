"""Pydantic schema for the engagement scope (``scope.yaml``)."""
from __future__ import annotations

import ipaddress
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field, field_validator


class EngagementWindow(BaseModel):
    start: datetime
    end: datetime


class ScopeDefinition(BaseModel):
    """Authoritative description of what is in-scope for the engagement."""

    engagement_id: str
    accounts: dict[Literal["aws", "gcp"], list[str]] = Field(default_factory=dict)
    domains: list[str] = Field(default_factory=list)
    ip_ranges: list[str] = Field(default_factory=list)
    excluded_resources: list[str] = Field(default_factory=list)
    engagement_window: EngagementWindow
    authorized_modules: list[str] = Field(default_factory=list)
    env_tag_required: str | None = None

    @field_validator("ip_ranges")
    @classmethod
    def _validate_networks(cls, value: list[str]) -> list[str]:
        for net in value:
            ipaddress.ip_network(net, strict=False)
        return value
