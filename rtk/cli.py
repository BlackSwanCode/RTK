"""Typer-based CLI entrypoint for RTK (V1)."""
from __future__ import annotations

import importlib
import inspect
import json
import uuid
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from rtk.core.findings.schema import Target
from rtk.core.findings.store import FindingsStore
from rtk.core.logging import configure, get_logger
from rtk.core.scope.parser import ScopeError, load_scope

console = Console()
app = typer.Typer(help="Red Team Toolkit V1 — authorized engagements only")
configure()
log = get_logger("cli")


@app.command("scope")
def scope_validate(path: Path = typer.Argument(..., exists=True)) -> None:
    try:
        scope = load_scope(path)
    except ScopeError as exc:
        console.print(f"[bold red]scope error:[/] {exc}")
        raise typer.Exit(code=2) from exc

    table = Table(title=f"Scope {scope.engagement_id}", show_lines=True)
    table.add_column("Field", style="cyan")
    table.add_column("Value")
    table.add_row("engagement_id", scope.engagement_id)
    table.add_row("window", f"{scope.engagement_window.start.isoformat()} -> {scope.engagement_window.end.isoformat()}")
    table.add_row("accounts", json.dumps(scope.accounts))
    table.add_row("authorized_modules", ", ".join(scope.authorized_modules) or "—")
    console.print(table)


@app.command("findings")
def findings_list(
    db: Path = typer.Option(..., "--db", exists=True, dir_okay=False),
    mission_id: str = typer.Option(..., "--mission-id"),
    severity: str | None = typer.Option(None, "--severity"),
) -> None:
    store = FindingsStore(db)
    filters = {"severity": severity} if severity else None
    findings = store.list(uuid.UUID(mission_id), filters)

    table = Table(title=f"Findings for {mission_id} ({len(findings)})")
    table.add_column("id", style="dim")
    table.add_column("module")
    table.add_column("severity")
    table.add_column("chain_hash", style="dim")
    table.add_column("summary")
    for f in findings:
        table.add_row(str(f.id)[:8], f.module, f.severity, f.chain_hash[:8] if f.chain_hash else "N/A", f.observed.summary[:50])
    console.print(table)

    if not store.verify_chain(uuid.UUID(mission_id)):
        console.print("[bold red]WARNING: Chain hash verification FAILED![/]")


@app.command("run")
def run_module(
    module: str = typer.Argument(..., help="dotted module path, e.g., demo.ping or iam.wildcard_policies"),
    target: str = typer.Option(..., "--target", help="JSON-encoded Target"),
    scope_path: Path = typer.Option(..., "--scope", exists=True, dir_okay=False),
    db: Path = typer.Option(..., "--db", dir_okay=False),
    mission_id: str = typer.Option(..., "--mission-id"),
    policies_dir: Path | None = typer.Option(None, "--policies-dir", dir_okay=True),
) -> None:
    scope = load_scope(scope_path)
    target_obj = Target.model_validate_json(target)
    store = FindingsStore(db)
    mid = uuid.UUID(mission_id)

    mod_name = f"rtk.modules.{module}"
    try:
        mod = importlib.import_module(mod_name)
    except ImportError as exc:
        console.print(f"[bold red]unknown module:[/] {mod_name}")
        raise typer.Exit(code=2) from exc

    kwargs = {"target": target_obj, "scope": scope, "store": store}
    sig = inspect.signature(mod.run)
    if "mission_id" in sig.parameters:
        kwargs["mission_id"] = mid
    if "policies_dir" in sig.parameters:
        if not policies_dir:
            console.print("[bold red]Error:[/] --policies-dir is required for this module")
            raise typer.Exit(code=2)
        kwargs["policies_dir"] = policies_dir

    result = mod.run(**kwargs)
    findings_count = len(result) if isinstance(result, list) else 1
    console.print(f"[bold green]Module executed. {findings_count} finding(s) emitted.[/]")
