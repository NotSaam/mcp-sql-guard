"""Servidor MCP: expone la base de datos a un agente de IA en solo lectura.

Configuración por variables de entorno:

- `MCP_SQL_DB`: ruta a la base de datos SQLite.
- `MCP_SQL_POLICY`: ruta al JSON de roles y llamantes.
- `MCP_SQL_TOKEN`: token del llamante (identifica el rol y sus filtros).
- `MCP_SQL_AUDIT`: ruta del registro de auditoría (opcional).
"""

from __future__ import annotations

import os
import sqlite3
from typing import Any

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp_types import ToolAnnotations

from .audit import AuditLog
from .guard import GuardedDatabase
from .policy import AccessDenied, Policy

READ_ONLY = ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=False)


def build_server(db: GuardedDatabase, audit: AuditLog) -> MCPServer:
    who = db.principal.name
    mcp = MCPServer(
        name="mcp-sql-guard",
        instructions=(
            "Read-only SQL access. Every table you see is already filtered to what the caller "
            "may access; hidden columns do not exist for you. Use list_tables and describe_table "
            "before writing a query. Only single SELECT statements are allowed."
        ),
    )

    def guarded(tool: str, fn, **args: Any):
        try:
            result = fn()
        except AccessDenied as exc:
            audit.record(principal=who, tool=tool, args=args, allowed=False, reason=str(exc))
            # ToolError llega al modelo como error con su mensaje; otras excepciones se ocultan.
            raise ToolError(f"access denied: {exc}") from exc
        except sqlite3.Error as exc:
            # SQL inválido o una escritura que SQLite rechaza antes del authorizer.
            audit.record(principal=who, tool=tool, args=args, allowed=False, reason=str(exc))
            raise ToolError(f"query error: {exc}") from exc
        audit.record(principal=who, tool=tool, args=args, allowed=True)
        return result

    @mcp.tool(annotations=READ_ONLY)
    def whoami() -> dict[str, Any]:
        """Return the caller's identity and role."""
        return {"principal": who, "role": db.principal.role.name}

    @mcp.tool(annotations=READ_ONLY)
    def list_tables() -> list[str]:
        """List the tables this caller can read."""
        return guarded("list_tables", db.list_tables)

    @mcp.tool(annotations=READ_ONLY)
    def describe_table(table: str) -> list[dict[str, str]]:
        """Return the visible columns and their types for a table."""
        return guarded("describe_table", lambda: db.describe_table(table), table=table)

    @mcp.tool(annotations=READ_ONLY)
    def query(sql: str, max_rows: int = 50) -> dict[str, Any]:
        """Run one read-only SELECT. Results are capped at max_rows."""

        def run():
            r = db.query(sql, max_rows=max_rows)
            return {"columns": r.columns, "rows": r.rows, "truncated": r.truncated}

        result = guarded("query", run, sql=sql)
        return result

    return mcp


def main() -> None:
    policy = Policy.load(os.environ["MCP_SQL_POLICY"])
    principal = policy.authenticate(os.environ.get("MCP_SQL_TOKEN"))
    db = GuardedDatabase(os.environ["MCP_SQL_DB"], principal)
    build_server(db, AuditLog(os.environ.get("MCP_SQL_AUDIT"))).run("stdio")


if __name__ == "__main__":
    main()
