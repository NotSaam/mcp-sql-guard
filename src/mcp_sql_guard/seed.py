"""Crea la base de datos de ejemplo: dos clubes, sus jugadores y sus sesiones.

    uv run python -m mcp_sql_guard.seed examples/demo.db
"""

from __future__ import annotations

import random
import sqlite3
import sys
from datetime import date, timedelta
from pathlib import Path

SCHEMA = """
CREATE TABLE clubs (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL
);
CREATE TABLE players (
    id INTEGER PRIMARY KEY,
    club_id INTEGER NOT NULL REFERENCES clubs(id),
    name TEXT NOT NULL,
    position TEXT NOT NULL,
    salary_eur INTEGER NOT NULL
);
CREATE TABLE sessions (
    id INTEGER PRIMARY KEY,
    club_id INTEGER NOT NULL REFERENCES clubs(id),
    player_id INTEGER NOT NULL REFERENCES players(id),
    day TEXT NOT NULL,
    minutes INTEGER NOT NULL,
    rpe INTEGER NOT NULL CHECK (rpe BETWEEN 1 AND 10),
    load INTEGER GENERATED ALWAYS AS (minutes * rpe) STORED
);
CREATE TABLE medical_notes (
    id INTEGER PRIMARY KEY,
    player_id INTEGER NOT NULL REFERENCES players(id),
    note TEXT NOT NULL
);
"""

PLAYERS = {
    1: [("Iker", "GK"), ("Martín", "DF"), ("Hugo", "MF"), ("Leo", "FW")],
    2: [("Pablo", "GK"), ("Álex", "DF"), ("Mateo", "MF"), ("Dani", "FW")],
}


def seed(path: str | Path) -> None:
    path = Path(path)
    path.unlink(missing_ok=True)
    rng = random.Random(7)
    with sqlite3.connect(path) as conn:
        conn.executescript(SCHEMA)
        conn.executemany("INSERT INTO clubs VALUES (?, ?)", [(1, "CD Atlántico"), (2, "UD Interior")])
        start = date(2026, 10, 1)
        for club_id, players in PLAYERS.items():
            for name, position in players:
                cur = conn.execute(
                    "INSERT INTO players (club_id, name, position, salary_eur) VALUES (?, ?, ?, ?)",
                    (club_id, name, position, rng.randrange(18_000, 60_000, 500)),
                )
                player_id = cur.lastrowid
                conn.execute(
                    "INSERT INTO medical_notes (player_id, note) VALUES (?, ?)",
                    (player_id, "Revisión rutinaria sin incidencias"),
                )
                for d in range(14):
                    conn.execute(
                        "INSERT INTO sessions (club_id, player_id, day, minutes, rpe) VALUES (?, ?, ?, ?, ?)",
                        (club_id, player_id, (start + timedelta(days=d)).isoformat(),
                         rng.choice([45, 60, 75, 90]), rng.randint(3, 9)),
                    )


if __name__ == "__main__":
    seed(sys.argv[1] if len(sys.argv) > 1 else "examples/demo.db")
