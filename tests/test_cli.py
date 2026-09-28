"""End-to-end CLI integration test."""
from typer.testing import CliRunner

from rtk.cli import app

runner = CliRunner()


def test_scope_validate(scope_yaml_path):
    result = runner.invoke(app, ["scope", str(scope_yaml_path)])
    assert result.exit_code == 0, result.output
    assert "ENG-TEST-001" in result.output


def test_run_demo_ping_end_to_end(scope_yaml_path, tmp_path, in_scope_target):
    db = tmp_path / "findings.sqlite"
    target_json = in_scope_target.model_dump_json()

    result = runner.invoke(
        app,
        [
            "run",
            "demo.ping",
            "--target",
            target_json,
            "--scope",
            str(scope_yaml_path),
            "--db",
            str(db),
        ],
    )
    assert result.exit_code == 0, result.output
    assert "finding emitted" in result.output

    # findings list
    result = runner.invoke(app, ["findings", "--db", str(db)])
    assert result.exit_code == 0, result.output
    assert "rtk.modules.demo.ping" in result.output
