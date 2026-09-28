"""Typer-based CLI entrypoint for RTK."""
from __future__ import annotations

import importlib
import json
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from rtk.core.findings.schema import Target
from rtk.core.findings.store import FindingsStore
from rtk.core.logging import configure, get_logger
from rtk.core.scope.parser import ScopeError, load_scope
from rtk.core.scope.schema import ScopeDefinition

console = Console()
app = typer.Typer(help="Red Team Toolkit — authorized engagements only")
configure()
log = get_logger("cli")


# --------------------------------------------------------------------------- #
# scope
# --------------------------------------------------------------------------- #
@app.command("scope")
def scope_validate(path: Path = typer.Argument(..., exists=True)) -> None:
    """Load and validate a scope.yaml, then print a Rich summary."""
    try:
        scope = load_scope(path)
    except ScopeError as exc:
        console.print(f"[bold red]scope error:[/] {exc}")
        raise typer.Exit(code=2) from exc

    table = Table(title=f"Scope {scope.engagement_id}", show_lines=True)
    table.add_column("Field", style="cyan")
    table.add_column("Value")
    table.add_row("engagement_id", scope.engagement_id)
    table.add_row("window_start", scope.engagement_window.start.isoformat())
    table.add_row("window_end", scope.engagement_window.end.isoformat())
    table.add_row("accounts", json.dumps(scope.accounts))
    table.add_row("domains", ", ".join(scope.domains) or "—")
    table.add_row("ip_ranges", ", ".join(scope.ip_ranges) or "—")
    table.add_row("excluded", ", ".join(scope.excluded_resources) or "—")
    table.add_row("authorized_modules", ", ".join(scope.authorized_modules) or "—")
    table.add_row("env_tag_required", scope.env_tag_required or "—")
    console.print(table)


# --------------------------------------------------------------------------- #
# findings
# --------------------------------------------------------------------------- #
@app.command("findings")
def findings_list(
    db: Path = typer.Option(..., "--db", exists=True, dir_okay=False),
    severity: str | None = typer.Option(None, "--severity"),
    module: str | None = typer.Option(None, "--module"),
) -> None:
    """List findings from a SQLite store as a Rich table."""
    store = FindingsStore(db)
    filters = {k: v for k, v in {"severity": severity, "module": module}.items() if v}
    findings = store.list(filters)

    table = Table(title=f"Findings ({len(findings)})")
    table.add_column("id", style="dim")
    table.add_column("timestamp")
    table.add_column("module")
    table.add_column("severity")
    table.add_column("exploit.")
    table.add_column("summary")
    for f in findings:
        table.add_row(
            str(f.id)[:8],
            f.timestamp_utc.isoformat(timespec="seconds"),
            f.module,
            f.severity,
            f.exploitability,
            f.observed.summary[:60],
        )
    console.print(table)


# --------------------------------------------------------------------------- #
# run
# --------------------------------------------------------------------------- #
@app.command("run")
def run_module(
    module: str = typer.Argument(..., help="dotted module path, e.g. demo.ping"),
    target: str = typer.Option(..., "--target", help="JSON-encoded Target"),
    scope_path: Path = typer.Option(..., "--scope", exists=True, dir_okay=False),
    db: Path = typer.Option(..., "--db", dir_okay=False),
) -> None:
    """Execute a module end-to-end: scope → run → store."""
    scope = load_scope(scope_path)
    target_obj = Target.model_validate_json(target)
    store = FindingsStore(db)

    mod_name = f"rtk.modules.{module}"
    try:
        mod = importlib.import_module(mod_name)
    except ImportError as exc:
        console.print(f"[bold red]unknown module:[/] {mod_name}")
        raise typer.Exit(code=2) from exc

    finding = mod.run(target=target_obj, scope=scope, store=store)
    console.print(f"[bold green]finding emitted:[/] {finding.id} ({finding.severity})")
