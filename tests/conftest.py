from pathlib import Path

import pytest

from mcp_sql_guard.guard import GuardedDatabase
from mcp_sql_guard.policy import Policy
from mcp_sql_guard.seed import seed

POLICY = Path(__file__).parent.parent / "examples" / "policy.json"

TOKENS = {
    "staff-atlantico": "demo-staff-atlantico",
    "staff-interior": "demo-staff-interior",
    "player-iker": "demo-player-iker",
}


@pytest.fixture(scope="session")
def db_path(tmp_path_factory) -> Path:
    path = tmp_path_factory.mktemp("db") / "demo.db"
    seed(path)
    return path


@pytest.fixture(scope="session")
def policy() -> Policy:
    return Policy.load(POLICY)


@pytest.fixture
def open_db(db_path, policy):
    opened: list[GuardedDatabase] = []

    def _open(who: str) -> GuardedDatabase:
        db = GuardedDatabase(db_path, policy.authenticate(TOKENS[who]))
        opened.append(db)
        return db

    yield _open
    for db in opened:
        db.close()
