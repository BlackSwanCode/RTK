"""RTK-01: Scan de secrets dans l'historique Git complet.

Wrapper autour de l'exécutable `gitleaks` pour détecter les secrets committés,
même s'ils ont été supprimés dans le HEAD.
"""
from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from uuid import UUID

from rtk.core.findings.schema import AttackSpec, Finding, Observed, Target
from rtk.core.findings.store import FindingsStore
from rtk.core.logging import get_logger
from rtk.core.scope.parser import assert_in_scope
from rtk.core.scope.schema import ScopeDefinition

log = get_logger("modules.secrets.multi_repo_scan")


def _run_gitleaks(repo_path: Path) -> list[dict]:
    """Exécute gitleaks en mode détection sur l'historique complet."""
    gitleaks_bin = shutil.which("gitleaks")
    if not gitleaks_bin:
        log.error("gitleaks_not_found", extra={"msg": "gitleaks executable not in PATH"})
        raise RuntimeError("gitleaks executable not found. Please install it.")

    cmd = [
        gitleaks_bin, "detect", 
        "--source", str(repo_path),
        "--log-opts", "--all",  # Scan tout l'historique git
        "--report-format", "json",
        "--no-git", # On suppose que le repo est déjà cloné, ou on utilise le dir git
    ]
    
    # Si c'est un repo git, on retire --no-git pour scanner l'historique
    if (repo_path / ".git").exists():
        cmd.remove("--no-git")
        cmd.extend(["--log-opts", "--all"])

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=False)
        if result.returncode == 1 or result.returncode == 2: # 1 = leaks found, 2 = error
            if result.stdout:
                return json.loads(result.stdout)
        return []
    except subprocess.SubprocessError as e:
        log.error("gitleaks_execution_failed", extra={"error": str(e), "stderr": result.stderr if 'result' in locals() else ""})
        return []


def run(
    target: Target,
    scope: ScopeDefinition,
    store: FindingsStore,
    mission_id: UUID,
    repos_dir: Path,
) -> list[Finding]:
    """Scanne les dépôts dans `repos_dir` et génère des findings pour chaque secret."""
    assert_in_scope(target, scope, module="rtk.modules.secrets.multi_repo_scan")
    log.info("secrets_scan_start", extra={"target": target.account_id, "repos_dir": str(repos_dir)})
    
    findings = []
    for repo_path in repos_dir.iterdir():
        if not repo_path.is_dir() or not (repo_path / ".git").exists():
            continue
            
        log.info("scanning_repo", extra={"repo": repo_path.name})
        leaks = _run_gitleaks(repo_path)
        
        for leak in leaks:
            # Déduplication simple par hash du secret + repo
            secret_hash = leak.get("Fingerprint", "")
            
            finding = Finding(
                mission_id=mission_id,
                module="rtk.modules.secrets.multi_repo_scan",
                vector="01",
                severity="critical" if "aws" in leak.get("RuleID", "").lower() or "gcp" in leak.get("RuleID", "").lower() else "high",
                exploitability="probable",
                atlas_technique="AML.T0051.000", # Secret Exposure
                owasp_llm="LLM06",
                target=target,
                attack=AttackSpec(
                    description=f"Secret found in git history: {leak.get('RuleID')}",
                    payload=repo_path.name,
                ),
                observed=Observed(
                    summary=f"File: {leak.get('File')}, Line: {leak.get('StartLine')}",
                    raw_truncated=leak.get("Secret", "")[:100] + "...[REDACTED]" # Ne jamais logger le secret complet
                ),
                expected_defense="Les secrets ne doivent jamais être committés. Utiliser des outils de pre-commit et des variables d'environnement chiffrées.",
                defense_bypassed=True,
                correlation={"repo": repo_path.name, "commit": leak.get("Commit", ""), "fingerprint": secret_hash},
                simulated_attack=False,
            )
            store.add(finding)
            findings.append(finding)
            
    log.info("secrets_scan_complete", extra={"findings_count": len(findings)})
    return findings