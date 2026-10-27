import sqlite3

import pytest

from mcp_sql_guard.guard import GuardedDatabase
from mcp_sql_guard.policy import AccessDenied


# --- Autenticación ---------------------------------------------------------


def test_rejects_missing_and_unknown_tokens(policy):
    with pytest.raises(AccessDenied):
        policy.authenticate(None)
    with pytest.raises(AccessDenied):
        policy.authenticate("not-a-real-token")


def test_token_maps_to_role_and_attributes(policy):
    p = policy.authenticate("demo-staff-interior")
    assert p.name == "staff-interior"
    assert p.role.name == "staff"
    assert p.attributes == {"club_id": 2}


# --- Filtro de filas -------------------------------------------------------


def test_staff_only_sees_own_club(open_db):
    db = open_db("staff-atlantico")
    clubs = {row[0] for row in db.query("SELECT DISTINCT club_id FROM sessions").rows}
    assert clubs == {1}
    assert db.query("SELECT name FROM clubs").rows == [["CD Atlántico"]]


def test_two_clubs_never_share_rows(open_db):
    a = {r[0] for r in open_db("staff-atlantico").query("SELECT id FROM players").rows}
    b = {r[0] for r in open_db("staff-interior").query("SELECT id FROM players").rows}
    assert a and b and a.isdisjoint(b)


def test_player_only_sees_own_sessions(open_db):
    db = open_db("player-iker")
    players = db.query("SELECT DISTINCT player_id FROM sessions").rows
    assert players == [[1]]


def test_filter_applies_through_subqueries_and_joins(open_db):
    db = open_db("staff-atlantico")
    rows = db.query(
        "SELECT c.name, COUNT(*) FROM sessions s JOIN clubs c ON c.id = s.club_id GROUP BY c.name"
    ).rows
    assert [r[0] for r in rows] == ["CD Atlántico"]


def test_row_filter_with_subquery_on_hidden_table(open_db):
    notes = open_db("staff-atlantico").query("SELECT player_id FROM medical_notes").rows
    assert {r[0] for r in notes} == {1, 2, 3, 4}


# --- Tablas y columnas -----------------------------------------------------


def test_tables_outside_role_are_invisible(open_db):
    db = open_db("player-iker")
    assert db.list_tables() == ["players", "sessions"]
    with pytest.raises(AccessDenied):
        db.query("SELECT * FROM medical_notes")


def test_hidden_column_does_not_exist(open_db):
    db = open_db("staff-atlantico")
    cols = [c["name"] for c in db.describe_table("players")]
    assert "salary_eur" not in cols
    with pytest.raises(sqlite3.OperationalError):
        db.query("SELECT salary_eur FROM players")


def test_cannot_bypass_view_with_main_prefix(open_db):
    # `main` está vacío: la base real vive en un esquema con nombre aleatorio.
    db = open_db("staff-atlantico")
    with pytest.raises(sqlite3.OperationalError, match="no such table"):
        db.query("SELECT * FROM main.sessions")
    with pytest.raises(sqlite3.OperationalError, match="no such table"):
        db.query("SELECT salary_eur FROM main.players")


@pytest.mark.parametrize(
    "sql",
    [
        # Una CTE con el nombre de una vista no debe dar acceso a la tabla real.
        "WITH players AS (SELECT * FROM main.players) SELECT * FROM players",
        "WITH s AS (SELECT * FROM main.players) SELECT * FROM s",
        "SELECT * FROM (SELECT * FROM main.sessions) AS sessions",
    ],
)
def test_cannot_bypass_view_with_ctes_or_subqueries(open_db, sql):
    db = open_db("player-iker")
    with pytest.raises((AccessDenied, sqlite3.OperationalError)):
        db.query(sql)


@pytest.mark.parametrize(
    "table",
    [
        "sqlite_master",
        "sqlite_temp_master",
        "temp.sqlite_master",
        # Las funciones tabla de PRAGMA revelarían el nombre del esquema real.
        "pragma_database_list",
        "pragma_table_list",
    ],
)
def test_cannot_read_schema_tables(open_db, table):
    with pytest.raises(AccessDenied):
        open_db("staff-atlantico").query(f"SELECT * FROM {table}")


def test_errors_do_not_leak_source_schema(open_db):
    db = open_db("staff-atlantico")
    with pytest.raises(sqlite3.OperationalError) as exc:
        db.query("SELECT salary_eur FROM players")
    assert "src_" not in str(exc.value)


# --- Solo lectura ----------------------------------------------------------


@pytest.mark.parametrize(
    "sql",
    [
        "INSERT INTO sessions (club_id, player_id, day, minutes, rpe) VALUES (1, 1, '2026-01-01', 10, 5)",
        "UPDATE players SET name = 'x'",
        "DELETE FROM sessions",
        "DROP VIEW sessions",
        "CREATE TABLE t (x)",
        "ATTACH DATABASE 'other.db' AS other",
        "PRAGMA table_info(players)",
        "SELECT load_extension('evil')",
    ],
)
def test_writes_and_escapes_are_denied(open_db, sql):
    with pytest.raises((AccessDenied, sqlite3.DatabaseError)):
        open_db("staff-atlantico").query(sql)


def test_only_one_statement_per_call(open_db):
    with pytest.raises(sqlite3.ProgrammingError):
        open_db("staff-atlantico").query("SELECT 1; SELECT 2")


# --- Límites ---------------------------------------------------------------


def test_results_are_capped(open_db):
    db = open_db("staff-atlantico")
    result = db.query("SELECT * FROM sessions", max_rows=5)
    assert len(result.rows) == 5
    assert result.truncated is True


def test_long_queries_time_out(db_path, policy):
    db = GuardedDatabase(db_path, policy.authenticate("demo-staff-atlantico"), timeout_s=0.05)
    try:
        with pytest.raises(AccessDenied, match="exceeded"):
            db.query(
                "WITH RECURSIVE n(x) AS (SELECT 1 UNION ALL SELECT x + 1 FROM n) SELECT COUNT(*) FROM n"
            )
    finally:
        db.close()
