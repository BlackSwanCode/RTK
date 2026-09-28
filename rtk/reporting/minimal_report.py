"""Minimal HTML reporting module for RTK findings."""
from __future__ import annotations

from pathlib import Path
from uuid import UUID

from jinja2 import Template

from rtk.core.findings.schema import Finding
from rtk.core.findings.store import FindingsStore
from rtk.core.logging import get_logger

log = get_logger("reporting.minimal")

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <title>RTK Rapport de Mission - {{ mission_id }}</title>
    <style>
        body { font-family: system-ui, sans-serif; line-height: 1.6; max-width: 900px; margin: 2rem auto; padding: 0 1rem; }
        h1 { color: #2c3e50; border-bottom: 2px solid #eee; padding-bottom: 0.5rem; }
        .finding { border: 1px solid #ddd; border-radius: 8px; padding: 1rem; margin-bottom: 1rem; }
        .severity-critical { border-left: 5px solid #e74c3c; background: #fdf2f2; }
        .severity-high { border-left: 5px solid #e67e22; background: #fef5e7; }
        .severity-medium { border-left: 5px solid #f1c40f; background: #fef9e7; }
        .severity-low { border-left: 5px solid #3498db; background: #ebf5fb; }
        .severity-info { border-left: 5px solid #95a5a6; background: #f4f6f7; }
        .meta { font-size: 0.9em; color: #666; margin-bottom: 0.5rem; }
        .payload { background: #2d3436; color: #dfe6e9; padding: 0.5rem; border-radius: 4px; font-family: monospace; overflow-x: auto; }
    </style>
</head>
<body>
    <h1>Rapport de findings RTK</h1>
    <p><strong>Mission ID:</strong> {{ mission_id }}</p>
    <p><strong>Total findings:</strong> {{ findings|length }}</p>

    {% for f in findings %}
    <div class="finding severity-{{ f.severity }}">
        <div class="meta">
            <strong>[{{ f.severity|upper }}]</strong> {{ f.module }} | {{ f.timestamp_utc.strftime('%Y-%m-%d %H:%M UTC') }}
        </div>
        <h3>{{ f.observed.summary }}</h3>
        <p><strong>Target:</strong> {{ f.target.cloud }} / {{ f.target.account_id }}</p>
        {% if f.attack.payload %}
        <div class="payload">{{ f.attack.payload }}</div>
        {% endif %}
        <p><strong>Defense Expected:</strong> {{ f.expected_defense }}</p>
    </div>
    {% else %}
    <p>Aucun finding enregistré pour cette mission.</p>
    {% endfor %}
</body>
</html>
"""

SEVERITY_ORDER = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}


def generate_report(store: FindingsStore, mission_id: UUID, output_path: Path) -> Path:
    """Generate an HTML report from the findings store, sorted by severity."""
    findings = store.list(mission_id)

    # Tri par sévérité décroissante, puis par timestamp
    sorted_findings = sorted(
        findings,
        key=lambda f: (SEVERITY_ORDER.get(f.severity, 0), f.timestamp_utc),
        reverse=True
    )

    template = Template(HTML_TEMPLATE)
    html_content = template.render(
        mission_id=str(mission_id),
        findings=sorted_findings
    )

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(html_content, encoding="utf-8")

    log.info("report_generated", extra={"path": str(output_path), "count": len(sorted_findings)})
    return output_path
