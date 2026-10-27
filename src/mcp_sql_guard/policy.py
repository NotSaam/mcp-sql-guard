"""Quién puede llamar al servidor y qué datos puede ver.

La política vive en un JSON (ver `examples/policy.json`):

- `roles`: por cada rol, las tablas visibles, el filtro de filas (SQL con
  parámetros `:club_id`, `:player_id`…) y las columnas ocultas.
- `principals`: cada llamante, identificado por el SHA-256 de su token.
  Nunca se guarda el token en claro.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


class AccessDenied(Exception):
    """El llamante no está autorizado para la operación pedida."""


@dataclass(frozen=True)
class TableRule:
    row_filter: str | None = None
    hidden_columns: frozenset[str] = frozenset()


@dataclass(frozen=True)
class Role:
    name: str
    tables: dict[str, TableRule]


@dataclass(frozen=True)
class Principal:
    name: str
    role: Role
    # Valores que sustituyen a los `:parametros` de los filtros de fila.
    attributes: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Policy:
    roles: dict[str, Role]
    _principals: dict[str, dict[str, Any]]

    @classmethod
    def load(cls, path: str | Path) -> Policy:
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
        roles = {
            name: Role(
                name=name,
                tables={
                    table: TableRule(
                        row_filter=rule.get("row_filter"),
                        hidden_columns=frozenset(rule.get("hidden_columns", [])),
                    )
                    for table, rule in spec["tables"].items()
                },
            )
            for name, spec in raw["roles"].items()
        }
        principals = {p["token_sha256"]: p for p in raw["principals"]}
        for p in principals.values():
            if p["role"] not in roles:
                raise ValueError(f"principal {p['name']!r} has unknown role {p['role']!r}")
        return cls(roles=roles, _principals=principals)

    def authenticate(self, token: str | None) -> Principal:
        if not token:
            raise AccessDenied("missing token")
        digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
        # Comparación en tiempo constante contra cada hash registrado.
        match = next((p for h, p in self._principals.items() if hmac.compare_digest(h, digest)), None)
        if match is None:
            raise AccessDenied("invalid token")
        return Principal(
            name=match["name"],
            role=self.roles[match["role"]],
            attributes=dict(match.get("attributes", {})),
        )


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()
