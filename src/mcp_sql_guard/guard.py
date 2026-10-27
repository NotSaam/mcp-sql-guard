"""Ejecución de consultas de solo lectura con control de acceso.

Cuatro capas, de fuera hacia dentro:

1. La base de datos real se adjunta en modo solo lectura (`mode=ro`): SQLite
   rechaza cualquier escritura aunque todo lo demás falle.
2. Se adjunta bajo un esquema con nombre aleatorio por conexión. `main` es una
   base vacía en memoria, así que `main.sessions` no lleva a ningún sitio, y
   el llamante no puede nombrar las tablas reales porque no conoce el esquema.
3. Por cada tabla permitida se crea una vista TEMP con el mismo nombre que
   aplica el filtro de filas y quita las columnas ocultas. `SELECT * FROM
   sessions` lee la vista filtrada.
4. Un *authorizer* de SQLite revisa cada operación del plan de la consulta:
   solo deja SELECT y lecturas de esas vistas (o de las tablas reales cuando
   la lectura la hace una de ellas). Las tablas `sqlite_*`, PRAGMA, ATTACH y
   cualquier escritura se deniegan.
"""

from __future__ import annotations

import re
import secrets
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .policy import AccessDenied, Principal

# Funciones SQL que podrían filtrar información fuera del modelo de vistas.
_BLOCKED_FUNCTIONS = frozenset({"load_extension", "readfile", "writefile", "edit", "fts3_tokenizer"})

# En los filtros de fila de la política, `main.` apunta a la base real.
_MAIN_PREFIX = re.compile(r"\bmain\.", re.IGNORECASE)


@dataclass(frozen=True)
class QueryResult:
    columns: list[str]
    rows: list[list[Any]]
    truncated: bool


class GuardedDatabase:
    def __init__(
        self,
        db_path: str | Path,
        principal: Principal,
        *,
        max_rows: int = 200,
        timeout_s: float = 2.0,
    ) -> None:
        self.principal = principal
        self.max_rows = max_rows
        self.timeout_s = timeout_s
        self._schema = f"src_{secrets.token_hex(16)}"
        self._conn = sqlite3.connect("file::memory:", uri=True, check_same_thread=False)
        source = f"file:{Path(db_path).resolve().as_posix()}?mode=ro"
        self._conn.execute("ATTACH DATABASE ? AS " + self._schema, (source,))
        self._views = self._create_views()
        self._conn.set_authorizer(self._authorize)

    def close(self) -> None:
        self._conn.close()

    # --- API pública -----------------------------------------------------

    def list_tables(self) -> list[str]:
        return sorted(self._views)

    def describe_table(self, table: str) -> list[dict[str, str]]:
        if table not in self._views:
            raise AccessDenied(f"table {table!r} is not available to role {self.principal.role.name!r}")
        return [{"name": c, "type": t} for c, t in self._views[table].items()]

    def query(self, sql: str, params: dict[str, Any] | None = None, max_rows: int | None = None) -> QueryResult:
        limit = min(max_rows or self.max_rows, self.max_rows)
        deadline = time.monotonic() + self.timeout_s
        # Corta consultas que tarden demasiado (p. ej. cross joins enormes).
        self._conn.set_progress_handler(lambda: 1 if time.monotonic() > deadline else 0, 10_000)
        try:
            cur = self._conn.execute(sql, params or {})
            rows = cur.fetchmany(limit + 1)
        except sqlite3.DatabaseError as exc:
            msg = str(exc).replace(self._schema, "<source>")
            if "not authorized" in msg or "prohibited" in msg:
                raise AccessDenied(msg) from exc
            if "interrupted" in msg:
                raise AccessDenied(f"query exceeded {self.timeout_s}s") from exc
            raise type(exc)(msg) from exc
        finally:
            self._conn.set_progress_handler(None, 0)
        columns = [d[0] for d in cur.description or []]
        return QueryResult(
            columns=columns,
            rows=[list(r) for r in rows[:limit]],
            truncated=len(rows) > limit,
        )

    # --- Internos --------------------------------------------------------

    def _create_views(self) -> dict[str, dict[str, str]]:
        """Crea una vista TEMP filtrada por tabla permitida. Devuelve sus columnas."""
        views: dict[str, dict[str, str]] = {}
        attrs = self.principal.attributes
        for table, rule in self.principal.role.tables.items():
            info = self._conn.execute(f'PRAGMA {self._schema}.table_info("{table}")').fetchall()
            if not info:
                raise ValueError(f"policy references missing table {table!r}")
            cols = {name: ctype for _, name, ctype, *_ in info if name not in rule.hidden_columns}
            select = ", ".join(f'"{c}"' for c in cols)
            where = ""
            if rule.row_filter:
                # Los valores del principal se incrustan como literales: una vista
                # no admite parámetros. Solo enteros o texto escapado.
                expr = _MAIN_PREFIX.sub(f"{self._schema}.", rule.row_filter)
                where = " WHERE " + _bind_literals(expr, attrs)
            self._conn.execute(
                f'CREATE TEMP VIEW "{table}" AS SELECT {select} FROM {self._schema}."{table}"{where}'
            )
            views[table] = cols
        return views

    def _authorize(self, action: int, arg1: str | None, arg2: str | None, db: str | None, source: str | None) -> int:
        if action == sqlite3.SQLITE_SELECT:
            return sqlite3.SQLITE_OK
        if action == sqlite3.SQLITE_READ:
            # El catálogo revela el SQL de las vistas, y con él el esquema real.
            if (arg1 or "").lower().startswith("sqlite_"):
                return sqlite3.SQLITE_DENY
            # Vistas TEMP, CTE (llegan sin esquema) y tablas reales leídas por una vista.
            # Una CTE con el nombre de una vista no basta para leer la base real:
            # haría falta conocer el nombre aleatorio del esquema.
            if db == "temp" or db is None or (db == self._schema and source in self._views):
                return sqlite3.SQLITE_OK
            return sqlite3.SQLITE_DENY
        if action == sqlite3.SQLITE_FUNCTION:
            return sqlite3.SQLITE_DENY if (arg2 or "").lower() in _BLOCKED_FUNCTIONS else sqlite3.SQLITE_OK
        if action == sqlite3.SQLITE_RECURSIVE:
            return sqlite3.SQLITE_OK
        return sqlite3.SQLITE_DENY


_PARAM = re.compile(r":([A-Za-z_]\w*)")


def _bind_literals(expr: str, attrs: dict[str, Any]) -> str:
    def literal(match: re.Match[str]) -> str:
        key = match.group(1)
        if key not in attrs:
            raise ValueError(f"row filter {expr!r} uses :{key}, which the principal does not define")
        value = attrs[key]
        if isinstance(value, bool) or not isinstance(value, (int, str)):
            raise ValueError(f"attribute {key!r} must be int or str")
        return str(value) if isinstance(value, int) else "'" + value.replace("'", "''") + "'"

    return _PARAM.sub(literal, expr)
