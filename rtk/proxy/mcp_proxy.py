"""Proxy MCP transparent (Passthrough strict).

Ce module relaie les requêtes JSON-RPC entre un client et un serveur MCP cible
sans aucune modification du payload, tout en journalisant la télémétrie.
"""
from __future__ import annotations

import hashlib
import json
import time
import uuid
from typing import Any

import httpx
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse

from rtk.core.findings.schema import MCPCall
from rtk.core.findings.store import FindingsStore
from rtk.core.logging import get_logger

log = get_logger("proxy.mcp")

app = FastAPI(title="RTK MCP Proxy")

# Variables globales injectées au démarrage
_proxy_state: dict[str, Any] = {}


def init_proxy(target_url: str, mission_id: str, store: FindingsStore) -> None:
    """Initialise l'état du proxy avant le démarrage du serveur."""
    _proxy_state["target_url"] = target_url.rstrip("/")
    _proxy_state["mission_id"] = mission_id
    _proxy_state["session_id"] = str(uuid.uuid4())
    _proxy_state["store"] = store
    log.info("proxy_initialized", extra={
        "target": target_url,
        "mission_id": mission_id,
        "session_id": _proxy_state["session_id"]
    })


def _truncate_and_hash(data: Any) -> tuple[str, str]:
    """Retourne (hash_sha256, résumé tronqué à 200 chars) d'un objet JSON."""
    json_str = json.dumps(data, sort_keys=True, default=str)
    hash_val = hashlib.sha256(json_str.encode("utf-8")).hexdigest()
    summary = json_str[:200] + ("..." if len(json_str) > 200 else "")
    return hash_val, summary


@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"])
async def proxy_request(path: str, request: Request) -> Response:
    """Relaie fidèlement la requête et journalise les appels JSON-RPC."""
    target_url = _proxy_state["target_url"]
    mission_id = _proxy_state["mission_id"]
    session_id = _proxy_state["session_id"]
    store: FindingsStore = _proxy_state["store"]

    # Reconstruction de l'URL cible
    target_endpoint = f"{target_url}/{path}"
    if request.url.query:
        target_endpoint += f"?{request.url.query}"

    headers = dict(request.headers)
    headers.pop("host", None)

    body_bytes = await request.body()

    start_time = time.perf_counter()
    success = False
    method = "unknown"
    tool_name = None
    args_hash, args_summary = "none", "none"
    result_hash, result_summary = "none", "none"

    try:
        # 1. Tentative de parsing JSON-RPC pour la journalisation
        if request.method == "POST" and body_bytes:
            try:
                payload = json.loads(body_bytes)
                if isinstance(payload, dict) and payload.get("jsonrpc") == "2.0":
                    method = payload.get("method", "unknown")
                    params = payload.get("params", {})
                    if method == "tools/call":
                        tool_name = params.get("name")

                    args_hash, args_summary = _truncate_and_hash(params)
            except json.JSONDecodeError:
                pass  # Ce n'est pas du JSON-RPC, on relaye quand même (passthrough)

        # 2. Forward de la requête (Strict Passthrough)
        async with httpx.AsyncClient() as client:
            resp = await client.request(
                method=request.method,
                url=target_endpoint,
                headers=headers,
                content=body_bytes,
                timeout=30.0
            )

            # 3. Parsing de la réponse pour la journalisation
            if resp.status_code == 200:
                try:
                    resp_payload = resp.json()
                    if isinstance(resp_payload, dict) and resp_payload.get("jsonrpc") == "2.0":
                        success = "error" not in resp_payload
                        result_hash, result_summary = _truncate_and_hash(resp_payload.get("result", {}))
                except json.JSONDecodeError:
                    success = True  # Considéré comme succès si pas d'erreur HTTP

            # 4. Journalisation structurée
            latency_ms = (time.perf_counter() - start_time) * 1000
            log.info("mcp_call_relayed", extra={
                "session_id": session_id,
                "method": method,
                "tool_name": tool_name,
                "args_hash": args_hash,
                "result_hash": result_hash,
                "latency_ms": round(latency_ms, 2),
                "success": success,
                "http_status": resp.status_code
            })

            # 5. Persistance en base
            mcp_call = MCPCall(
                mission_id=uuid.UUID(mission_id),
                session_id=session_id,
                method=method,
                tool_name=tool_name,
                args_hash=args_hash,
                args_summary=args_summary,
                result_hash=result_hash,
                result_summary=result_summary,
                latency_ms=latency_ms,
                success=success
            )
            store.add_mcp_call(mcp_call)

            # 6. Retour de la réponse inchangée
            return Response(
                content=resp.content,
                status_code=resp.status_code,
                headers=dict(resp.headers)
            )

    except httpx.RequestError as exc:
        latency_ms = (time.perf_counter() - start_time) * 1000
        log.error("mcp_call_failed", extra={
            "session_id": session_id, "method": method, "error": str(exc), "latency_ms": round(latency_ms, 2)
        })
        return JSONResponse(status_code=502, content={"error": "Bad Gateway: Target MCP unreachable"})
