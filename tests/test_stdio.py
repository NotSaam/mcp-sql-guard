"""Extremo a extremo: el servidor arranca como subproceso y se le habla por stdio."""

import os
import sys

from mcp import Client
from mcp.client.stdio import StdioServerParameters

from .conftest import POLICY


def _params(db_path, token, audit_path):
    env = {
        **os.environ,
        "MCP_SQL_DB": str(db_path),
        "MCP_SQL_POLICY": str(POLICY),
        "MCP_SQL_TOKEN": token,
        "MCP_SQL_AUDIT": str(audit_path),
    }
    return StdioServerParameters(command=sys.executable, args=["-m", "mcp_sql_guard.server"], env=env)


async def test_stdio_round_trip(db_path, tmp_path):
    audit = tmp_path / "audit.jsonl"
    async with Client(_params(db_path, "demo-staff-interior", audit)) as client:
        who = await client.call_tool("whoami", {})
        assert who.structured_content == {"principal": "staff-interior", "role": "staff"}

        result = await client.call_tool("query", {"sql": "SELECT DISTINCT club_id FROM sessions"})
        assert result.structured_content["rows"] == [[2]]

        denied = await client.call_tool("query", {"sql": "DELETE FROM sessions"})
        assert denied.is_error

    assert audit.read_text(encoding="utf-8").count('"allowed": false') == 1
