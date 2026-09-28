"""Load and enforce the engagement scope."""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from rtk.core.findings.schema import Target
from rtk.core.scope.schema import ScopeDefinition


class ScopeError(RuntimeError):
    """Base class for scope-related failures."""


class OutOfScopeError(ScopeError):
    """Raised when a target falls outside the signed engagement scope."""


class ModuleNotAuthorizedError(ScopeError):
    """Raised when a module is not listed in ``authorized_modules``."""


class EngagementWindowClosedError(ScopeError):
    """Raised when the current time is outside the engagement window."""


def load_scope(path: str | Path) -> ScopeDefinition:
    """Parse a ``scope.yaml`` file into a :class:`ScopeDefinition`."""
    p = Path(path)
    if not p.exists():
        raise ScopeError(f"scope file not found: {p}")
    raw: dict[str, Any] = yaml.safe_load(p.read_text()) or {}
    return ScopeDefinition.model_validate(raw)


def assert_in_scope(
    target: Target,
    scope: ScopeDefinition,
    *,
    module: str | None = None,
) -> None:
    """Raise if ``target`` (or ``module``) is not covered by ``scope``.

    This is the non-negotiable gate every active module MUST call before
    performing any network interaction.
    """
    # Engagement window
    now = datetime.now(timezone.utc)
    if not (scope.engagement_window.start <= now <= scope.engagement_window.end):
        raise EngagementWindowClosedError(
            f"engagement {scope.engagement_id} is not active at {now.isoformat()}"
        )

    # Module allow-list
    if module is not None and scope.authorized_modules:
        if module not in scope.authorized_modules:
            raise ModuleNotAuthorizedError(
                f"module {module!r} is not authorized in scope {scope.engagement_id}"
            )

    # Account
    allowed_accounts = scope.accounts.get(target.cloud, [])
    if target.account_id not in allowed_accounts:
        raise OutOfScopeError(
            f"account {target.account_id} ({target.cloud}) not in scope"
        )

    # Explicit exclusion
    if target.resource_arn and target.resource_arn in scope.excluded_resources:
        raise OutOfScopeError(
            f"resource {target.resource_arn} is explicitly excluded"
        )
