"""SQLite-backed Findings Store.

.. note::
    TODO(V1): swap ``sqlite3`` for ``sqlcipher3`` (or ``pysqlcipher3``) to
    encrypt the database at rest. The public API (``add`` / ``list`` /
    ``export_json``) must remain unchanged.
"""
from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

from rtk.core.findings.schema import Finding
from rtk.core.logging import get_logger

log = get_logger("findings.store")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS findings (
    id            TEXT PRIMARY KEY,
    timestamp_utc TEXT NOT NULL,
    module        TEXT NOT NULL,
    vector        TEXT NOT NULL,
    severity      TEXT NOT NULL,
    exploitability TEXT NOT NULL,
    payload       TEXT NOT NULL
);
"""


class FindingsStore:
    """Thin wrapper around a SQLite file storing serialized findings."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.executescript(_SCHEMA)
        log.info("findings_store_initialized", extra={"path": str(self.path)})

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(str(self.path))
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def add(self, finding: Finding) -> None:
        """Persist a finding."""
        payload = finding.model_dump_json()
        with self._connect() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO findings "
                "(id, timestamp_utc, module, vector, severity, exploitability, payload) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    str(finding.id),
                    finding.timestamp_utc.isoformat(),
                    finding.module,
                    finding.vector,
                    finding.severity,
                    finding.exploitability,
                    payload,
                ),
            )
        log.info(
            "finding_added",
            extra={
                "module": finding.module,
                "severity": finding.severity,
                "id": str(finding.id),
            },
        )

    def list(self, filters: dict[str, Any] | None = None) -> list[Finding]:
        """Return findings matching optional filters (severity, module, vector)."""
        filters = filters or {}
        where_clauses: list[str] = []
        params: list[Any] = []
        for key in ("severity", "module", "vector"):
            if key in filters and filters[key] is not None:
                where_clauses.append(f"{key} = ?")
                params.append(filters[key])
        query = "SELECT payload FROM findings"
        if where_clauses:
            query += " WHERE " + " AND ".join(where_clauses)
        query += " ORDER BY timestamp_utc DESC"

        with self._connect() as conn:
            rows = conn.execute(query, params).fetchall()
        return [Finding.model_validate_json(row[0]) for row in rows]

    def export_json(self, path: str | Path) -> Path:
        """Dump every finding as a JSON array."""
        out = Path(path)
        out.parent.mkdir(parents=True, exist_ok=True)
        findings = self.list()
        out.write_text(
            json.dumps(
                [f.model_dump(mode="json") for f in findings],
                indent=2,
                default=str,
            )
        )
        log.info("findings_exported", extra={"path": str(out), "count": len(findings)})
        return out
