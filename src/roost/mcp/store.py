# SPDX-License-Identifier: MIT
# Copyright (c) 2026 sol pbc

"""Bearer tokens for agents enrolled through the MCP server, in D1.

A token is the agent's only credential, so roost stores just its SHA-256: a
token is valid while its hash is here and its account is active."""

import secrets

from .. import directory
from ..encoding import b64url_encode, sha256_b64url

TOKEN_PREFIX = "rmcp_"

SCHEMA = [
    """CREATE TABLE IF NOT EXISTS mcp_tokens (
  token_hash TEXT PRIMARY KEY,
  did TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
)""",
    "CREATE INDEX IF NOT EXISTS idx_mcp_tokens_did ON mcp_tokens(did)",
]

_initialized = False


class TokenError(ValueError):
    pass


async def init_tokens(db) -> None:
    global _initialized
    await directory.init_directory(db)
    if not _initialized:
        await db.batch([(statement, []) for statement in SCHEMA])
        _initialized = True


def is_token(value: str) -> bool:
    return value.startswith(TOKEN_PREFIX)


async def issue_token(db, did: str) -> str:
    await init_tokens(db)
    token = TOKEN_PREFIX + b64url_encode(secrets.token_bytes(32))
    await db.run("INSERT INTO mcp_tokens (token_hash, did) VALUES (?, ?)", sha256_b64url(token), did)
    return token


async def resolve_token(db, token: str) -> dict:
    """{did, do_id} for a live token; raises TokenError."""
    await init_tokens(db)
    row = await db.first(
        """SELECT t.did, a.do_id FROM mcp_tokens t
           JOIN accounts a ON a.did = t.did AND a.active = 1 WHERE t.token_hash = ?""",
        sha256_b64url(token),
    )
    if not row:
        raise TokenError("MCP token could not be verified")
    return {"did": row["did"], "do_id": row["do_id"]}
