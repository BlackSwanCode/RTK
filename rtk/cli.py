"""Typer-based CLI entrypoint for RTK (Unified V5+).

This module serves as the single entry point for all Red Team Toolkit operations.
It enforces scope validation, structured logging, and safe execution of modules.
"""
from __future__ import annotations

import asyncio
import inspect
import json
import tempfile
import threading
import time
import uuid
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import typer
import yaml
from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.table import Table

from rtk.core.cloud.verify import verify_env_tag
from rtk.core.findings.schema import Target
from rtk.core.findings.store import FindingsStore
from rtk.core.judge.protocol import DeterministicJudge
from rtk.core.logging import configure, get_logger
from rtk.core.scope.parser import ScopeError, assert_in_scope, load_scope
from rtk.harness.corpus_runner import load_corpus, run_case
from rtk.reporting.minimal_report import generate_report

console = Console()
app = typer.Typer(
    help="Red Team Toolkit (RTK) — Authorized offensive security tooling only.",
    no_args_is_help=True,
)

# Initialize structured JSON logging at the module level
configure()
log = get_logger("cli")


# =============================================================================
# SCOPE COMMANDS
# =============================================================================
@app.command("scope")
def scope_validate(
    path: Path = typer.Argument(..., exists=True, dir_okay=False, help="Path to scope.yaml")
) -> None:
    """Load and validate a scope.yaml, then print a Rich summary."""
    try:
        scope = load_scope(path)
    except ScopeError as exc:
        console.print(f"[bold red]Scope Error:[/] {exc}")
        raise typer.Exit(code=2) from exc

    table = Table(title=f"Scope Validation: {scope.engagement_id}", show_lines=True)
    table.add_column("Field", style="cyan", width=20)
    table.add_column("Value")
    table.add_row("engagement_id", scope.engagement_id)
    table.add_row(
        "window",
        f"{scope.engagement_window.start.isoformat()} → {scope.engagement_window.end.isoformat()}",
    )
    table.add_row("accounts", json.dumps(scope.accounts))
    table.add_row("domains", ", ".join(scope.domains) or "—")
    table.add_row("ip_ranges", ", ".join(scope.ip_ranges) or "—")
    table.add_row("excluded", ", ".join(scope.excluded_resources) or "—")
    table.add_row("authorized_modules", ", ".join(scope.authorized_modules) or "—")
    table.add_row("env_tag_required", scope.env_tag_required or "—")

    console.print(table)
    console.print("[bold green]✓ Scope is valid and parseable.[/]")


# =============================================================================
# FINDINGS COMMANDS
# =============================================================================
@app.command("findings")
def findings_list(
    db: Path = typer.Option(..., "--db", exists=True, dir_okay=False, help="Path to findings SQLite database"),
    mission_id: str = typer.Option(..., "--mission-id", help="UUID of the mission"),
    severity: str | None = typer.Option(None, "--severity", help="Filter by severity"),
    module: str | None = typer.Option(None, "--module", help="Filter by module name"),
) -> None:
    """List findings from a SQLite store as a Rich table."""
    try:
        mid = uuid.UUID(mission_id)
    except ValueError:
        console.print("[bold red]Error:[/] Invalid UUID for --mission-id")
        raise typer.Exit(code=2)

    store = FindingsStore(db)
    filters = {k: v for k, v in {"severity": severity, "module": module}.items() if v}
    findings = store.list(mid, filters)

    table = Table(title=f"Findings for Mission {mission_id} ({len(findings)} total)")
    table.add_column("ID", style="dim", width=8)
    table.add_column("Timestamp", width=19)
    table.add_column("Module", width=30)
    table.add_column("Severity", width=10)
    table.add_column("Exploit.", width=10)
    table.add_column("Chain Hash", style="dim", width=10)
    table.add_column("Summary", width=50)

    for f in findings:
        severity_style = (
            "red" if f.severity == "critical"
            else "yellow" if f.severity == "high"
            else "white"
        )
        table.add_row(
            str(f.id)[:8],
            f.timestamp_utc.isoformat(timespec="seconds"),
            f.module,
            f"[{severity_style}]{f.severity}[/{severity_style}]",
            f.exploitability,
            f.chain_hash[:8] if f.chain_hash else "N/A",
            f.observed.summary[:47] + "..." if len(f.observed.summary) > 50 else f.observed.summary,
        )
    console.print(table)

    if findings and not store.verify_chain(mid):
        console.print(
            "\n[bold red blink]⚠️ WARNING: Chain hash verification FAILED! "
            "Data integrity compromised. ⚠️[/]"
        )


# =============================================================================
# REPORT COMMANDS
# =============================================================================
@app.command("report")
def generate_report_cmd(
    db: Path = typer.Option(..., "--db", exists=True, dir_okay=False),
    mission_id: str = typer.Option(..., "--mission-id"),
    output: Path = typer.Option(..., "--output", dir_okay=False, help="Output HTML file path"),
) -> None:
    """Generate a minimal HTML report for a given mission."""
    try:
        mid = uuid.UUID(mission_id)
    except ValueError:
        console.print("[bold red]Error:[/] Invalid UUID for --mission-id")
        raise typer.Exit(code=2)

    store = FindingsStore(db)
    out_path = generate_report(store, mid, output)
    console.print(f"[bold green]✓ Report generated successfully:[/] {out_path.absolute()}")


# =============================================================================
# PROXY COMMANDS
# =============================================================================
@app.command("proxy")
def proxy_start(
    target: str = typer.Option(..., "--target", help="Target URL, e.g., mcp://127.0.0.1:9000"),
    listen_port: int = typer.Option(8080, "--listen", help="Port to listen on"),
    scope_path: Path = typer.Option(..., "--scope", exists=True, dir_okay=False),
    db: Path = typer.Option(..., "--db", dir_okay=False),
    mission_id: str = typer.Option(..., "--mission-id"),
    mode: str = typer.Option("passthrough", "--mode", help="passthrough, enforce, or poison"),
    enforce_allowlist: str | None = typer.Option(None, "--enforce-allowlist", help="Comma-separated allowed tools"),
    poison_tool: str | None = typer.Option(None, "--poison-tool", help="Tool name to poison"),
    poison_payload: str | None = typer.Option(None, "--poison-payload", help="JSON payload to inject"),
    timeout_minutes: int = typer.Option(30, "--timeout", help="Poison mode auto-deactivation time"),
    i_understand_poison_mode: bool = typer.Option(
        False, "--i-understand-poison-mode", is_flag=True, help="REQUIRED for poison mode"
    ),
) -> None:
    """Start an MCP proxy (passthrough, enforce, or poison) after strict scope validation."""

    # 1. Parse target and create a pseudo-Target object for scope verification
    parsed = urlparse(target)
    if parsed.scheme not in ("mcp", "http", "https"):
        console.print("[bold red]Error:[/] Target must use 'mcp://', 'http://', or 'https://' scheme")
        raise typer.Exit(code=2)

    # Derive a target object (fallback to generic AWS if not specified, adjusted by scope)
    target_obj = Target(
        cloud="aws",
        account_id=parsed.hostname.replace(".", "")[:12] if parsed.hostname else "000000000000",
        region="us-east-1",
    )

    scope = load_scope(scope_path)
    try:
        assert_in_scope(target_obj, scope, module="rtk.proxy.mcp_proxy")
    except ScopeError as exc:
        console.print(f"[bold red]Scope Violation:[/] {exc}")
        raise typer.Exit(code=2)

    # 2. CRITICAL GUARDRAIL: Poison mode requires explicit flag AND environment verification
    if mode == "poison":
        if not i_understand_poison_mode:
            console.print(
                "[bold red]ERROR:[/] Poison mode requires the explicit "
                "`--i-understand-poison-mode` flag."
            )
            raise typer.Exit(code=2)

        try:
            verify_env_tag(target_obj.cloud, target_obj.account_id, target_obj.region)
        except Exception as e:
            console.print(f"[bold red]Fail-Closed:[/] Environment tag verification failed. {e}")
            console.print(
                "[bold yellow]Action:[/] Ensure the target resource has the required "
                "redteam authorization tag."
            )
            raise typer.Exit(code=2)

    # 3. Initialize Store and Proxy State
    store = FindingsStore(db)
    from rtk.proxy import mcp_proxy

    mcp_proxy.init_proxy(
        target_url=target,
        mission_id=mission_id,
        store=store,
        mode=mode,
        enforce_allowlist=enforce_allowlist.split(",") if enforce_allowlist else None,
        poison_tool=poison_tool,
        poison_payload=poison_payload,
        timeout_minutes=timeout_minutes,
    )

    # 4. Continuous Rich Banner for Poison Mode
    def poison_banner_task() -> None:
        banner_text = (
            "[bold red blink]⚠️ POISON MODE ACTIVE ⚠️\n"
            f"Target: {target}\n"
            f"Tool: {poison_tool}\n"
            f"Auto-deactivates in {timeout_minutes} mins of inactivity."
        )
        with Live(
            Panel(banner_text, border_style="red", expand=False), refresh_per_second=2
        ) as live:
            while mcp_proxy._proxy_state["mode"] == "poison":
                time.sleep(1)
            live.update(
                Panel(
                    "[bold yellow]Poison mode deactivated (timeout or manual).[/]",
                    border_style="yellow",
                    expand=False,
                )
            )

    banner_thread = None
    if mode == "poison":
        banner_thread = threading.Thread(target=poison_banner_task, daemon=True)
        banner_thread.start()

    console.print(
        f"[bold green]✓ Starting MCP Proxy[/] on port {listen_port} → {target} (Mode: {mode})"
    )
    console.print(f"Session ID: {mcp_proxy._proxy_state['session_id']}")

    # 5. Start Uvicorn Server
    import uvicorn

    uvicorn.run(mcp_proxy.app, host="0.0.0.0", port=listen_port, log_level="warning")


# =============================================================================
# RUN COMMANDS (Module Orchestrator)
# =============================================================================
@app.command("run")
def run_module(
    module: str = typer.Argument(
        ...,
        help="Dotted module path, e.g., demo.ping, iam.wildcard_policies, buckets.enum_buckets",
    ),
    target: str = typer.Option(..., "--target", help="JSON-encoded Target object"),
    scope_path: Path = typer.Option(..., "--scope", exists=True, dir_okay=False),
    db: Path = typer.Option(..., "--db", dir_okay=False),
    mission_id: str = typer.Option(..., "--mission-id"),
    # --- Module-specific optional arguments (resolved dynamically) ---
    policies_dir: Path | None = typer.Option(None, "--policies-dir", dir_okay=True, help="Directory with IAM policies (RTK-07)"),
    org: str | None = typer.Option(None, "--org", help="Org name for bucket enumeration (RTK-04)"),
    envs: str | None = typer.Option(None, "--envs", help="Comma-separated envs for bucket enum (RTK-04)"),
    corpus_dir: Path | None = typer.Option(None, "--corpus", dir_okay=True, help="Corpus directory for LLM tests (RTK-10/11)"),
    judge_type: str = typer.Option("deterministic", "--judge", help="Judge type for corpus runner"),
    proxy_port: int = typer.Option(8080, "--proxy-port", help="Port of the running proxy to test against"),
    ogc_endpoints: str | None = typer.Option(None, "--ogc-endpoints", help="Comma-separated OGC URLs (RTK-20)"),
    repos_dir: Path | None = typer.Option(None, "--repos-dir", dir_okay=True, help="Directory with git repos (RTK-01)"),
    mcp_endpoint: str | None = typer.Option(None, "--mcp-endpoint", help="MCP server URL for tool watch/exfil (RTK-13/14)"),
    baseline_file: Path | None = typer.Option(None, "--baseline-file", help="Baseline JSON for tool watch (RTK-13)"),
    listener_url: str | None = typer.Option(None, "--listener-url", help="Exfil listener URL (RTK-14)"),
    endpoints: str | None = typer.Option(None, "--endpoints", help="Comma-separated URLs for error leakage (RTK-02)"),
    buckets_file: Path | None = typer.Option(None, "--buckets-file", help="JSON file with bucket list (RTK-05)"),
    domains: str | None = typer.Option(None, "--domains", help="Comma-separated domains for surface mapping (RTK-08)"),
    storage_accounts: str | None = typer.Option(None, "--storage-accounts", help="Comma-separated Azure storage accounts"),
) -> None:
    """Execute a module end-to-end: scope validation → execution → store."""

    try:
        mid = uuid.UUID(mission_id)
        target_obj = Target.model_validate_json(target)
    except Exception as e:
        console.print(f"[bold red]Error parsing target or mission_id:[/] {e}")
        raise typer.Exit(code=2)

    scope = load_scope(scope_path)
    store = FindingsStore(db)

    # 1. Scope Validation (Non-negotiable)
    try:
        assert_in_scope(target_obj, scope, module=f"rtk.modules.{module}")
    except ScopeError as exc:
        console.print(f"[bold red]Scope Violation:[/] {exc}")
        raise typer.Exit(code=2)

    # 2. Dynamic Module Import
    mod_name = f"rtk.modules.{module}"
    try:
        mod = __import__(mod_name, fromlist=["run"])
    except ImportError as exc:
        console.print(f"[bold red]Unknown module:[/] {mod_name}")
        raise typer.Exit(code=2) from exc

    # 3. Dynamic Argument Resolution
    kwargs: dict[str, Any] = {
        "target": target_obj,
        "scope": scope,
        "store": store,
        "mission_id": mid,
    }
    sig = inspect.signature(mod.run)

    # Map CLI options to function signature if they exist
    if "policies_dir" in sig.parameters and policies_dir:
        kwargs["policies_dir"] = policies_dir

    if "conventions_yaml" in sig.parameters:
        if not (org and envs):
            console.print("[bold red]Error:[/] --org and --envs are required for bucket enumeration")
            raise typer.Exit(code=2)
        conventions = [
            {
                "org": org,
                "envs": [e.strip() for e in envs.split(",")],
                "suffixes": ["data", "logs", "backup", "assets", "tiles", "raw", "dem", "radar"],
            }
        ]
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as tmp:
            yaml.safe_dump({"conventions": conventions}, tmp)
            kwargs["conventions_yaml"] = Path(tmp.name)

    if "corpus_dir" in sig.parameters and corpus_dir:
        kwargs["corpus_dir"] = corpus_dir
        # Special handling for corpus runner which is async and needs proxy URL
        if module == "llm_mcp.corpus":
            kwargs["proxy_url"] = f"http://127.0.0.1:{proxy_port}"
            kwargs["judge"] = DeterministicJudge() if judge_type == "deterministic" else None

    if "ogc_endpoints" in sig.parameters and ogc_endpoints:
        kwargs["ogc_endpoints"] = [e.strip() for e in ogc_endpoints.split(",")]

    if "repos_dir" in sig.parameters and repos_dir:
        kwargs["repos_dir"] = repos_dir

    if "mcp_endpoint" in sig.parameters and mcp_endpoint:
        kwargs["mcp_endpoint"] = mcp_endpoint

    if "baseline_file" in sig.parameters and baseline_file:
        kwargs["baseline_file"] = baseline_file

    if "listener_url" in sig.parameters and listener_url:
        kwargs["listener_url"] = listener_url

    if "endpoints" in sig.parameters and endpoints:
        kwargs["endpoints"] = [e.strip() for e in endpoints.split(",")]

    if "buckets" in sig.parameters and buckets_file:
        try:
            kwargs["buckets"] = json.loads(buckets_file.read_text())
        except Exception as e:
            console.print(f"[bold red]Error reading buckets file:[/] {e}")
            raise typer.Exit(code=2)

    if "domains" in sig.parameters and domains:
        kwargs["domains"] = [d.strip() for d in domains.split(",")]

    if "storage_accounts" in sig.parameters and storage_accounts:
        kwargs["storage_accounts"] = [a.strip() for a in storage_accounts.split(",")]

    # 4. Execution
    console.print(f"[bold cyan]▶ Executing module:[/] {mod_name}")

    if module == "llm_mcp.corpus":
        # Async execution for corpus runner
        async def _run_all() -> None:
            cases = load_corpus(corpus_dir)
            findings_count = 0
            for case in cases:
                finding = await run_case(
                    case=case,
                    proxy_url=kwargs["proxy_url"],
                    judge=kwargs["judge"],
                    store=store,
                    target=target_obj,
                    mission_id=mid,
                )
                if finding:
                    findings_count += 1
                    console.print(
                        f"  [red]BYPASS/FAIL:[/] {case.id} - {finding.observed.summary[:60]}"
                    )
                else:
                    console.print(f"  [green]PASS/SKIP:[/] {case.id}")
            console.print(f"\n[bold]Corpus complete. {findings_count} finding(s) generated.[/]")

        asyncio.run(_run_all())
    else:
        # Synchronous execution for standard modules
        result = mod.run(**kwargs)
        findings_count = len(result) if isinstance(result, list) else 1
        console.print(
            f"[bold green]✓ Module executed successfully. {findings_count} finding(s) emitted.[/]"
        )


if __name__ == "__main__":
    app()
