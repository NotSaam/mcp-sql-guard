import json

import pytest
from mcp.server.mcpserver.exceptions import ToolError

from mcp_sql_guard.audit import AuditLog
from mcp_sql_guard.server import build_server


def _payload(result):
    return result.structured_content


@pytest.fixture
def server(open_db, tmp_path):
    audit_path = tmp_path / "audit.jsonl"
    return build_server(open_db("player-iker"), AuditLog(audit_path)), audit_path


async def test_tools_are_registered_and_read_only(server):
    mcp, _ = server
    tools = {t.name: t for t in await mcp.list_tools()}
    assert set(tools) == {"whoami", "list_tables", "describe_table", "query"}
    assert all(t.annotations.read_only_hint for t in tools.values())


async def test_query_tool_returns_filtered_rows(server):
    mcp, _ = server
    result = await mcp.call_tool("query", {"sql": "SELECT DISTINCT player_id FROM sessions"})
    assert _payload(result)["rows"] == [[1]]


async def test_every_call_is_audited(server):
    mcp, audit_path = server
    await mcp.call_tool("list_tables", {})
    with pytest.raises(ToolError, match="access denied"):
        await mcp.call_tool("query", {"sql": "SELECT * FROM medical_notes"})

    events = [json.loads(line) for line in audit_path.read_text(encoding="utf-8").splitlines()]
    assert [(e["tool"], e["allowed"]) for e in events] == [("list_tables", True), ("query", False)]
    assert all(e["principal"] == "player-iker" for e in events)
