"""Tests du proxy MCP transparent (V3)."""
import json
import uuid
from pathlib import Path

import pytest
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from rtk.core.findings.store import FindingsStore
from rtk.proxy import mcp_proxy


@pytest.fixture
def mock_mcp_server():
    """Fixture: Un serveur MCP factice minimal répondant aux appels JSON-RPC."""
    app = FastAPI()

    @app.api_route("/{path:path}", methods=["GET", "POST"])
    async def handle_mcp(request: Request, path: str):
        body = await request.json()
        if body.get("method") == "tools/call":
            tool_name = body["params"].get("name")
            if tool_name == "get_weather":
                result = {"content": [{"type": "text", "text": "Sunny, 25°C"}]}
            else:
                result = {"content": [{"type": "text", "text": "Unknown tool"}]}
            return JSONResponse({"jsonrpc": "2.0", "id": body["id"], "result": result})
        return JSONResponse({"jsonrpc": "2.0", "id": body.get("id"), "error": {"code": -32601, "message": "Method not found"}})

    return app


@pytest.mark.asyncio
async def test_proxy_passthrough_and_logging(tmp_path, scope_yaml_path, mock_mcp_server):
    """Vérifie que le proxy relaie fidèlement et logue dans la base."""
    db_path = tmp_path / "test.sqlite"
    store = FindingsStore(db_path, encryption_key="test-key")
    mission_id = str(uuid.uuid4())

    # Initialisation du proxy pour pointer vers une URL factive (le test interceptera httpx)
    mcp_proxy.init_proxy("http://mock-mcp-target", mission_id, store)

    # Simulation d'une requête entrante vers le proxy
    from rtk.proxy.mcp_proxy import proxy_request
    from unittest.mock import patch, AsyncMock

    request_payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": "get_weather", "arguments": {"location": "Paris"}}
    }

    # Mock de la requête FastAPI
    mock_request = AsyncMock()
    mock_request.method = "POST"
    mock_request.url.path = "/message"
    mock_request.url.query = ""
    mock_request.headers = {"content-type": "application/json", "host": "localhost:8080"}
    mock_request.body = AsyncMock(return_value=json.dumps(request_payload).encode())

    # Mock de la réponse du serveur cible (simulant mock_mcp_server)
    mock_response_payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "result": {"content": [{"type": "text", "text": "Sunny, 25°C"}]}
    }

    with patch("rtk.proxy.mcp_proxy.httpx.AsyncClient") as mock_client_class:
        mock_client = AsyncMock()
        mock_response = AsyncMock()
        mock_response.status_code = 200
        mock_response.json.return_value = mock_response_payload
        mock_response.content = json.dumps(mock_response_payload).encode()
        mock_response.headers = {"content-type": "application/json"}
        mock_client.request = AsyncMock(return_value=mock_response)
        mock_client_class.return_value.__aenter__.return_value = mock_client

        # Exécution du proxy
        response = await proxy_request(path="message", request=mock_request)

        # 1. Vérification du Passthrough
        assert response.status_code == 200
        assert json.loads(response.body) == mock_response_payload

        # 2. Vérification de la journalisation en base
        calls = store.list_mcp_calls(uuid.UUID(mission_id))
        assert len(calls) == 1
        call = calls[0]

        assert call.method == "tools/call"
        assert call.tool_name == "get_weather"
        assert call.success is True
        assert call.latency_ms > 0

        # Vérification que le hachage et le troncature fonctionnent
        assert len(call.args_hash) == 64  # SHA-256
        assert "location" in call.args_summary
        assert "Sunny" in call.result_summary
