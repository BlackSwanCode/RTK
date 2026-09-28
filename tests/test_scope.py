"""Scope loading and enforcement tests."""
import pytest

from rtk.core.scope.parser import (
    ModuleNotAuthorizedError,
    OutOfScopeError,
    assert_in_scope,
    load_scope,
)


def test_load_scope(scope_yaml_path):
    scope = load_scope(scope_yaml_path)
    assert scope.engagement_id == "ENG-TEST-001"
    assert "111111111111" in scope.accounts["aws"]


def test_assert_in_scope_ok(scope, in_scope_target):
    # Must not raise
    assert_in_scope(in_scope_target, scope, module="rtk.modules.demo.ping")


def test_assert_in_scope_account_rejected(scope, out_of_scope_target):
    with pytest.raises(OutOfScopeError):
        assert_in_scope(out_of_scope_target, scope)


def test_assert_in_scope_module_rejected(scope, in_scope_target):
    with pytest.raises(ModuleNotAuthorizedError):
        assert_in_scope(
            in_scope_target, scope, module="rtk.modules.evil.not_allowed"
        )
