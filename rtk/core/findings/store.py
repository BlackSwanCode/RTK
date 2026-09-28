"""SQLCipher-backed Findings Store with chain hashing."""
from __future__ import annotations

import hashlib
import json
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator
from uuid import UUID

try:
    import sqlcipher3 as sqlite3  # type: ignore
except ImportError:
    raise RuntimeError("sqlcipher3 is required for RTK V1. Install via 'poetry add sqlcipher3'")

from rtk.core.findings.schema import Finding, MCPCall
from rtk.core.logging import get_logger

log = get_logger("findings.store")

_SCHEMA = """
PRAGMA key = 'rtk-dev-key'; -- TODO(V2): externalize via env var
CREATE TABLE IF NOT EXISTS findings (
    id            TEXT PRIMARY KEY,
    mission_id    TEXT NOT NULL,
    timestamp_utc TEXT NOT NULL,
    module        TEXT NOT NULL,
    vector        TEXT NOT NULL,
    severity      TEXT NOT NULL,
    exploitability TEXT NOT NULL,
    chain_hash    TEXT,
    payload       TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_mission ON findings(mission_id);
"""

_MCP_CALLS_SCHEMA = """
CREATE TABLE IF NOT EXISTS mcp_calls (
    id            TEXT PRIMARY KEY,
    mission_id    TEXT NOT NULL,
    session_id    TEXT NOT NULL,
    timestamp_utc TEXT NOT NULL,
    method        TEXT NOT NULL,
    tool_name     TEXT,
    args_hash     TEXT NOT NULL,
    args_summary  TEXT NOT NULL,
    result_hash   TEXT NOT NULL,
    result_summary TEXT NOT NULL,
    latency_ms    REAL NOT NULL,
    success       INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_mcp_mission ON mcp_calls(mission_id);
"""


class FindingsStore:
    def __init__(self, path: str | Path, encryption_key: str = "rtk-dev-key") -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.encryption_key = encryption_key
        self._init_db()

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.execute(f"PRAGMA key = '{self.encryption_key}'")
            conn.executescript(_SCHEMA + _MCP_CALLS_SCHEMA)
        log.info("findings_store_initialized", extra={"path": str(self.path)})

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(str(self.path))
        conn.execute(f"PRAGMA key = '{self.encryption_key}'")
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def _get_last_chain_hash(self, mission_id: UUID) -> str | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT chain_hash FROM findings WHERE mission_id = ? ORDER BY timestamp_utc DESC LIMIT 1",
                (str(mission_id),)
            ).fetchone()
            return row[0] if row else None

    def add(self, finding: Finding) -> None:
        prev_hash = self._get_last_chain_hash(finding.mission_id) or "GENESIS"
        payload_dict = finding.model_dump(exclude={"chain_hash"}, mode="json")
        hash_input = f"{prev_hash}{json.dumps(payload_dict, sort_keys=True)}"
        new_hash = hashlib.sha256(hash_input.encode("utf-8")).hexdigest()
        finding.chain_hash = new_hash

        payload_json = finding.model_dump_json()
        with self._connect() as conn:
            conn.execute(
                """INSERT INTO findings
                   (id, mission_id, timestamp_utc, module, vector, severity, exploitability, chain_hash, payload)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    str(finding.id), str(finding.mission_id), finding.timestamp_utc.isoformat(),
                    finding.module, finding.vector, finding.severity, finding.exploitability,
                    new_hash, payload_json,
                ),
            )
        log.info("finding_added", extra={"module": finding.module, "severity": finding.severity, "mission_id": str(finding.mission_id)})

    def list(self, mission_id: UUID, filters: dict[str, Any] | None = None) -> list[Finding]:
        filters = filters or {}
        where_clauses = ["mission_id = ?"]
        params: list[Any] = [str(mission_id)]
        for key in ("severity", "module", "vector"):
            if key in filters and filters[key] is not None:
                where_clauses.append(f"{key} = ?")
                params.append(filters[key])

        query = "SELECT payload FROM findings WHERE " + " AND ".join(where_clauses) + " ORDER BY timestamp_utc ASC"
        with self._connect() as conn:
            rows = conn.execute(query, params).fetchall()
        return [Finding.model_validate_json(row[0]) for row in rows]

    def verify_chain(self, mission_id: UUID) -> bool:
        """Vérifie l'intégrité de la chaîne de hachage pour une mission."""
        findings = self.list(mission_id)
        if not findings:
            return True

        prev_hash = "GENESIS"
        for f in findings:
            payload_dict = f.model_dump(exclude={"chain_hash"}, mode="json")
            expected_hash = hashlib.sha256(f"{prev_hash}{json.dumps(payload_dict, sort_keys=True)}".encode("utf-8")).hexdigest()
            if f.chain_hash != expected_hash:
                log.error("chain_hash_mismatch", extra={"mission_id": str(mission_id), "finding_id": str(f.id)})
                return False
            prev_hash = f.chain_hash
        return True

    def export_json(self, mission_id: UUID, path: str | Path) -> Path:
        out = Path(path)
        out.parent.mkdir(parents=True, exist_ok=True)
        findings = self.list(mission_id)
        out.write_text(json.dumps([f.model_dump(mode="json") for f in findings], indent=2, default=str))
        return out

    def add_mcp_call(self, call: MCPCall) -> None:
        """Persiste un appel MCP (télémétrie) dans la base chiffrée."""
        with self._connect() as conn:
            conn.execute(
                """INSERT INTO mcp_calls
                   (id, mission_id, session_id, timestamp_utc, method, tool_name,
                    args_hash, args_summary, result_hash, result_summary, latency_ms, success)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    str(call.id), str(call.mission_id), call.session_id, call.timestamp_utc.isoformat(),
                    call.method, call.tool_name, call.args_hash, call.args_summary,
                    call.result_hash, call.result_summary, call.latency_ms, int(call.success),
                ),
            )

    def list_mcp_calls(self, mission_id: UUID) -> list[MCPCall]:
        """Liste la télémétrie MCP pour une mission (non couvert par le chain_hash des findings)."""
        with self._connect() as conn:
            rows = conn.execute(
                """SELECT id, mission_id, session_id, timestamp_utc, method, tool_name,
                          args_hash, args_summary, result_hash, result_summary, latency_ms, success
                   FROM mcp_calls WHERE mission_id = ? ORDER BY timestamp_utc ASC""",
                (str(mission_id),),
            ).fetchall()
        return [
            MCPCall(
                id=r[0], mission_id=r[1], session_id=r[2], timestamp_utc=r[3], method=r[4],
                tool_name=r[5], args_hash=r[6], args_summary=r[7], result_hash=r[8],
                result_summary=r[9], latency_ms=r[10], success=bool(r[11]),
            )
            for r in rows
        ]
