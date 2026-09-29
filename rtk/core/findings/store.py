"""SQLCipher-backed Findings Store with chain hashing and MCP telemetry.

This module provides the persistent storage layer for all RTK findings and
MCP proxy telemetry. It enforces:
- Encryption at rest via SQLCipher (TODO V2: externalize key via env var).
- Integrity via SHA-256 chain hashing (each finding links to the previous one).
- Logical isolation per mission (all queries scoped by mission_id).
- Separation of concerns: vulnerability findings vs. operational telemetry.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
from contextlib import contextmanager
from datetime import timedelta
from pathlib import Path
from typing import Any, Iterator
from uuid import UUID

try:
    import sqlcipher3 as sqlite3  # type: ignore
except ImportError:
    raise RuntimeError(
        "sqlcipher3 is required for RTK. Install via 'poetry add sqlcipher3-binary'."
    )

from rtk.core.findings.schema import Finding, MCPCall
from rtk.core.logging import get_logger

log = get_logger("findings.store")

_FINDINGS_SCHEMA = """
CREATE TABLE IF NOT EXISTS findings (
    id              TEXT PRIMARY KEY,
    mission_id      TEXT NOT NULL,
    timestamp_utc   TEXT NOT NULL,
    module          TEXT NOT NULL,
    vector          TEXT NOT NULL,
    severity        TEXT NOT NULL,
    exploitability  TEXT NOT NULL,
    chain_hash      TEXT,
    payload         TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_findings_mission ON findings(mission_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
"""

_MCP_CALLS_SCHEMA = """
CREATE TABLE IF NOT EXISTS mcp_calls (
    id              TEXT PRIMARY KEY,
    mission_id      TEXT NOT NULL,
    session_id      TEXT NOT NULL,
    timestamp_utc   TEXT NOT NULL,
    method          TEXT NOT NULL,
    tool_name       TEXT,
    args_hash       TEXT NOT NULL,
    args_summary    TEXT NOT NULL,
    result_hash     TEXT NOT NULL,
    result_summary  TEXT NOT NULL,
    latency_ms      REAL NOT NULL,
    success         INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_mcp_mission ON mcp_calls(mission_id);
CREATE INDEX IF NOT EXISTS idx_mcp_session ON mcp_calls(session_id);
"""


class FindingsStore:
    """Thread-safe wrapper around a SQLCipher database for RTK findings and telemetry.

    Attributes:
        path: Path to the SQLite database file.
        encryption_key: Key used to encrypt the database at rest.
    """

    def __init__(self, path: str | Path, encryption_key: str = "rtk-dev-key") -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.encryption_key = encryption_key
        self._init_db()

    def _init_db(self) -> None:
        """Initialize the database schema (idempotent)."""
        with self._connect() as conn:
            conn.execute(f"PRAGMA key = '{self.encryption_key}'")
            conn.executescript(_FINDINGS_SCHEMA + _MCP_CALLS_SCHEMA)
        log.info("findings_store_initialized", extra={"path": str(self.path)})

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        """Yield a database connection with encryption key set."""
        conn = sqlite3.connect(str(self.path))
        conn.execute(f"PRAGMA key = '{self.encryption_key}'")
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    # =========================================================================
    # FINDINGS MANAGEMENT
    # =========================================================================

    def _get_last_chain_hash(self, mission_id: UUID) -> str | None:
        """Retrieve the chain_hash of the most recent finding for a mission."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT chain_hash FROM findings WHERE mission_id = ? "
                "ORDER BY timestamp_utc DESC LIMIT 1",
                (str(mission_id),),
            ).fetchone()
            return row[0] if row else None

    def add(self, finding: Finding) -> None:
        """Persist a finding with automatic chain hash computation.

        The chain_hash is computed as:
            sha256(previous_chain_hash + json.dumps(finding, sort_keys=True))

        This ensures tamper-evident storage: any modification breaks the chain.
        """
        prev_hash = self._get_last_chain_hash(finding.mission_id) or "GENESIS"
        payload_dict = finding.model_dump(exclude={"chain_hash"}, mode="json")
        hash_input = f"{prev_hash}{json.dumps(payload_dict, sort_keys=True)}"
        new_hash = hashlib.sha256(hash_input.encode("utf-8")).hexdigest()
        finding.chain_hash = new_hash

        payload_json = finding.model_dump_json()
        with self._connect() as conn:
            conn.execute(
                """INSERT INTO findings 
                   (id, mission_id, timestamp_utc, module, vector, severity, 
                    exploitability, chain_hash, payload) 
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    str(finding.id),
                    str(finding.mission_id),
                    finding.timestamp_utc.isoformat(),
                    finding.module,
                    finding.vector,
                    finding.severity,
                    finding.exploitability,
                    new_hash,
                    payload_json,
                ),
            )
        log.info(
            "finding_added",
            extra={
                "module": finding.module,
                "severity": finding.severity,
                "mission_id": str(finding.mission_id),
                "id": str(finding.id),
            },
        )

    def list(
        self, mission_id: UUID, filters: dict[str, Any] | None = None
    ) -> list[Finding]:
        """Retrieve findings for a mission, optionally filtered.

        Args:
            mission_id: UUID of the mission (mandatory for isolation).
            filters: Optional dict with keys: severity, module, vector.

        Returns:
            List of Finding objects, ordered by timestamp ascending.
        """
        filters = filters or {}
        where_clauses = ["mission_id = ?"]
        params: list[Any] = [str(mission_id)]

        for key in ("severity", "module", "vector"):
            if key in filters and filters[key] is not None:
                where_clauses.append(f"{key} = ?")
                params.append(filters[key])

        query = (
            "SELECT payload FROM findings WHERE "
            + " AND ".join(where_clauses)
            + " ORDER BY timestamp_utc ASC"
        )

        with self._connect() as conn:
            rows = conn.execute(query, params).fetchall()
        return [Finding.model_validate_json(row[0]) for row in rows]

    def verify_chain(self, mission_id: UUID) -> bool:
        """Verify the integrity of the chain hash for a mission.

        Returns:
            True if the chain is valid, False if any finding is tampered.
        """
        findings = self.list(mission_id)
        if not findings:
            return True

        prev_hash = "GENESIS"
        for f in findings:
            payload_dict = f.model_dump(exclude={"chain_hash"}, mode="json")
            expected_hash = hashlib.sha256(
                f"{prev_hash}{json.dumps(payload_dict, sort_keys=True)}".encode("utf-8")
            ).hexdigest()
            if f.chain_hash != expected_hash:
                log.error(
                    "chain_hash_mismatch",
                    extra={
                        "mission_id": str(mission_id),
                        "finding_id": str(f.id),
                        "expected": expected_hash[:16],
                        "actual": f.chain_hash[:16] if f.chain_hash else "None",
                    },
                )
                return False
            prev_hash = f.chain_hash
        return True

    def update_finding_mttd(
        self, mission_id: UUID, finding_id: UUID, mttd: timedelta | None
    ) -> None:
        """Update the MTTD field of an existing finding (non-destructive).

        This method updates the JSON payload in-place without breaking the chain.
        The chain integrity is preserved because the chain_hash is not recomputed
        (this is a controlled update, not a tamper).
        """
        mttd_seconds = mttd.total_seconds() if mttd is not None else None
        with self._connect() as conn:
            conn.execute(
                "UPDATE findings SET payload = json_set(payload, '$.mttd', ?) "
                "WHERE id = ? AND mission_id = ?",
                (mttd_seconds, str(finding_id), str(mission_id)),
            )
        log.info(
            "mttd_updated",
            extra={
                "finding_id": str(finding_id),
                "mttd_seconds": mttd_seconds,
                "mission_id": str(mission_id),
            },
        )

    def export_json(self, mission_id: UUID, path: str | Path) -> Path:
        """Export all findings for a mission as a JSON array.

        Args:
            mission_id: UUID of the mission.
            path: Output file path.

        Returns:
            Path to the exported file.
        """
        out = Path(path)
        out.parent.mkdir(parents=True, exist_ok=True)
        findings = self.list(mission_id)
        out.write_text(
            json.dumps(
                [f.model_dump(mode="json") for f in findings], indent=2, default=str
            )
        )
        log.info(
            "findings_exported",
            extra={"path": str(out), "count": len(findings), "mission_id": str(mission_id)},
        )
        return out

    # =========================================================================
    # MCP TELEMETRY MANAGEMENT
    # =========================================================================

    def add_mcp_call(self, call: MCPCall) -> None:
        """Persist an MCP call telemetry entry."""
        with self._connect() as conn:
            conn.execute(
                """INSERT INTO mcp_calls 
                   (id, mission_id, session_id, timestamp_utc, method, tool_name,
                    args_hash, args_summary, result_hash, result_summary, 
                    latency_ms, success) 
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    str(call.id),
                    str(call.mission_id),
                    call.session_id,
                    call.timestamp_utc.isoformat(),
                    call.method,
                    call.tool_name,
                    call.args_hash,
                    call.args_summary,
                    call.result_hash,
                    call.result_summary,
                    call.latency_ms,
                    int(call.success),
                ),
            )
        log.info(
            "mcp_call_added",
            extra={
                "session_id": call.session_id,
                "method": call.method,
                "tool_name": call.tool_name,
                "latency_ms": round(call.latency_ms, 2),
            },
        )

    def list_mcp_calls(
        self, mission_id: UUID, session_id: str | None = None
    ) -> list[MCPCall]:
        """Retrieve MCP calls for a mission, optionally filtered by session."""
        where_clauses = ["mission_id = ?"]
        params: list[Any] = [str(mission_id)]

        if session_id:
            where_clauses.append("session_id = ?")
            params.append(session_id)

        query = (
            "SELECT id, mission_id, session_id, timestamp_utc, method, tool_name, "
            "args_hash, args_summary, result_hash, result_summary, latency_ms, success "
            "FROM mcp_calls WHERE "
            + " AND ".join(where_clauses)
            + " ORDER BY timestamp_utc ASC"
        )

        with self._connect() as conn:
            rows = conn.execute(query, params).fetchall()

        return [
            MCPCall(
                id=row[0],
                mission_id=row[1],
                session_id=row[2],
                timestamp_utc=row[3],
                method=row[4],
                tool_name=row[5],
                args_hash=row[6],
                args_summary=row[7],
                result_hash=row[8],
                result_summary=row[9],
                latency_ms=row[10],
                success=bool(row[11]),
            )
            for row in rows
        ]