# mcp-sql-guard

Servidor [MCP](https://modelcontextprotocol.io) que da a un agente de IA acceso **de solo lectura** a una base de datos SQL, con **control de acceso por llamante**: cada token ve solo sus tablas, sus filas y sus columnas, y cada llamada queda en un registro de auditoría.

El ejemplo usa datos de fútbol (clubes, jugadores, sesiones de entrenamiento y notas médicas): el cuerpo técnico de un club solo ve su club, y un jugador solo ve sus propias sesiones.

## Cómo protege los datos

| Capa | Qué hace |
| --- | --- |
| Solo lectura | La base real se adjunta con `mode=ro`: SQLite rechaza cualquier escritura. |
| Esquema oculto | La base real vive bajo un esquema con nombre aleatorio por conexión; `main` está vacío. El agente no puede nombrar las tablas reales. |
| Vistas filtradas | Por cada tabla permitida se crea una vista con el filtro de filas del rol y sin las columnas ocultas. `SELECT * FROM sessions` lee la vista. |
| Authorizer de SQLite | Revisa cada operación del plan: solo deja `SELECT` y lecturas de las vistas. Deniega `PRAGMA`, `ATTACH`, el catálogo `sqlite_*`, `load_extension` y cualquier escritura. |
| Límites | Una sola sentencia por llamada, filas máximas por resultado y tiempo máximo por consulta. |
| Auditoría | Una línea JSON por llamada: quién, qué herramienta, qué consulta, si se permitió y por qué no. |

Los tokens se guardan como hash SHA-256 y se comparan en tiempo constante.

## Herramientas MCP

| Herramienta | Descripción |
| --- | --- |
| `whoami` | Identidad y rol del llamante. |
| `list_tables` | Tablas visibles para el llamante. |
| `describe_table` | Columnas visibles y sus tipos. |
| `query` | Ejecuta un `SELECT` (resultado limitado a `max_rows`). |

Todas se declaran con `readOnlyHint: true`.

## Política de acceso

[`examples/policy.json`](examples/policy.json) define roles y llamantes:

```json
"staff": {
  "tables": {
    "players":  { "row_filter": "club_id = :club_id", "hidden_columns": ["salary_eur"] },
    "sessions": { "row_filter": "club_id = :club_id" },
    "medical_notes": {
      "row_filter": "player_id IN (SELECT id FROM main.players WHERE club_id = :club_id)"
    }
  }
}
```

Los `:parametros` salen de los `attributes` de cada llamante (por ejemplo `{"club_id": 1}`). En los filtros, `main.` se refiere a la base real.

## Arrancar

Requisitos: Python 3.12+ y [uv](https://docs.astral.sh/uv/).

```bash
uv sync
uv run python -m mcp_sql_guard.seed examples/demo.db
```

Configuración para un cliente MCP (Claude Desktop, Claude Code…):

```json
{
  "mcpServers": {
    "football-db": {
      "command": "uv",
      "args": ["--directory", "/ruta/a/mcp-sql-guard", "run", "mcp-sql-guard"],
      "env": {
        "MCP_SQL_DB": "examples/demo.db",
        "MCP_SQL_POLICY": "examples/policy.json",
        "MCP_SQL_TOKEN": "demo-staff-atlantico",
        "MCP_SQL_AUDIT": "audit.jsonl"
      }
    }
  }
}
```

Tokens de demostración: `demo-staff-atlantico` (club 1), `demo-staff-interior` (club 2) y `demo-player-iker` (jugador 1). Son solo para el ejemplo; en un despliegue real genera los tuyos y guarda únicamente su hash.

## Tests

```bash
uv run pytest
```

34 tests: aislamiento entre clubes y jugadores, columnas ocultas, intentos de saltarse las vistas (`main.`, CTE con el mismo nombre que una vista, subconsultas), catálogo y funciones `pragma_*`, escrituras, varias sentencias, límites de filas y tiempo, auditoría, y una prueba de extremo a extremo que arranca el servidor por stdio.

## Limitaciones

- Ejemplo sobre SQLite. En PostgreSQL lo natural es delegar el filtro de filas en Row-Level Security con un rol de solo lectura.
- La identidad del llamante llega por variable de entorno (transporte stdio). Para HTTP habría que validar un token OAuth por petición.
