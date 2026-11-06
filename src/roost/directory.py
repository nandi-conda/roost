# SPDX-License-Identifier: MIT
# Copyright (c) 2026 sol pbc

"""The D1 account directory: accounts, invites, quotas, config, takedowns.

`db` is the D1 adapter (see platform.py): async first/all/run/batch, where run
returns the number of changed rows and batch takes (sql, params) pairs.
"""

import asyncio
import json
import secrets

SCHEMA = [
    """CREATE TABLE IF NOT EXISTS accounts (
  did TEXT PRIMARY KEY,
  handle TEXT NOT NULL UNIQUE,
  do_id TEXT NOT NULL,
  jwk_thumbprint TEXT,
  active INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
)""",
    "CREATE INDEX IF NOT EXISTS idx_accounts_handle ON accounts(handle)",
    "CREATE INDEX IF NOT EXISTS idx_accounts_thumbprint ON accounts(jwk_thumbprint)",
    """CREATE TABLE IF NOT EXISTS invite_quotas (
  did TEXT PRIMARY KEY,
  quota INTEGER NOT NULL CHECK (quota >= 0)
)""",
    """CREATE TABLE IF NOT EXISTS invites (
  token TEXT PRIMARY KEY,
  minted_by TEXT,
  minted_at TEXT NOT NULL DEFAULT (datetime('now')),
  spent_by_did TEXT,
  spent_at TEXT,
  idempotency_key TEXT,
  CHECK (
    (spent_by_did IS NULL AND spent_at IS NULL)
    OR (spent_by_did IS NOT NULL AND spent_at IS NOT NULL)
  )
)""",
    "CREATE INDEX IF NOT EXISTS idx_invites_minted_by ON invites(minted_by)",
    "CREATE INDEX IF NOT EXISTS idx_invites_minted_at ON invites(minted_at, token)",
    """CREATE TABLE IF NOT EXISTS config (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL,
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
)""",
    "INSERT INTO config (key, value) VALUES ('invite_quota_default', '3') ON CONFLICT DO NOTHING",
    """CREATE TABLE IF NOT EXISTS takedowns (
  did TEXT NOT NULL,
  handle TEXT NOT NULL,
  actor TEXT NOT NULL,
  records_deleted INTEGER NOT NULL,
  blobs_deleted INTEGER NOT NULL,
  collections TEXT NOT NULL,
  taken_down_at TEXT NOT NULL DEFAULT (datetime('now'))
)""",
]
# Only keyed (idempotent) mints are constrained; un-keyed rows keep NULL.
INVITES_IDEMPOTENCY_INDEX = (
    "CREATE UNIQUE INDEX IF NOT EXISTS idx_invites_idempotency_key "
    "ON invites(idempotency_key) WHERE idempotency_key IS NOT NULL"
)

INVITE_TOKEN_ALPHABET = "0123456789abcdefghjkmnpqrstvwxyz"
INVITE_TOKEN_LENGTH = 10
INIT_MAX_ATTEMPTS = 3
INIT_RETRY_BASE_S = 0.025


class DirectoryInitError(Exception):
    """Schema init failed after retries; the app maps it to a retryable 503."""


class RepoNotFoundError(Exception):
    pass


_idempotency_ensured = False


async def _ensure_invite_idempotency(db) -> None:
    global _idempotency_ensured
    if _idempotency_ensured:
        return
    columns = await db.all("PRAGMA table_info(invites)")
    if not any(column["name"] == "idempotency_key" for column in columns):
        await db.run("ALTER TABLE invites ADD COLUMN idempotency_key TEXT")
    await db.run(INVITES_IDEMPOTENCY_INDEX)
    _idempotency_ensured = True


async def init_directory(db) -> None:
    # The first D1 op after idle can lose an init race; a quick retry succeeds.
    last_error = None
    for attempt in range(1, INIT_MAX_ATTEMPTS + 1):
        try:
            await db.batch([(statement, []) for statement in SCHEMA])
            await _ensure_invite_idempotency(db)
            return
        except Exception as exc:
            last_error = exc
            if attempt < INIT_MAX_ATTEMPTS:
                await asyncio.sleep(INIT_RETRY_BASE_S * attempt)
    raise DirectoryInitError(
        f"Directory initialization failed after {INIT_MAX_ATTEMPTS} attempts: {last_error}"
    ) from last_error


async def resolve_repo(db, repo: str) -> dict:
    column = "did" if ":" in repo else "handle"
    row = await db.first(f"SELECT did, do_id FROM accounts WHERE {column} = ? AND active = 1", repo)
    if not row:
        raise RepoNotFoundError(f"Repository not found: {repo}")
    return {"did": row["did"], "do_id": row["do_id"]}


async def resolve_by_thumbprint(db, thumbprint: str) -> dict:
    row = await db.first("SELECT did, do_id FROM accounts WHERE jwk_thumbprint = ? AND active = 1", thumbprint)
    if not row:
        raise RepoNotFoundError("No account found for thumbprint")
    return {"did": row["did"], "do_id": row["do_id"]}


async def insert_account(db, did: str, handle: str, do_id: str, jwk_thumbprint: str | None = None) -> None:
    await db.run(
        "INSERT INTO accounts (did, handle, do_id, jwk_thumbprint) VALUES (?, ?, ?, ?)",
        did, handle, do_id, jwk_thumbprint,
    )


async def resolve_account_for_takedown(db, did: str) -> dict | None:
    row = await db.first("SELECT did, handle, do_id FROM accounts WHERE did = ?", did)
    return {"did": row["did"], "handle": row["handle"], "do_id": row["do_id"]} if row else None


async def deactivate_account(db, did: str) -> None:
    await db.run("UPDATE accounts SET active = 0 WHERE did = ?", did)


async def finalize_takedown(db, did, handle, actor, records_deleted, blobs_deleted, collections) -> None:
    await db.batch([
        ("DELETE FROM accounts WHERE did = ?", [did]),
        ("DELETE FROM oauth_sessions WHERE did = ?", [did]),
        ("DELETE FROM oauth_tokens WHERE did = ?", [did]),
        ("DELETE FROM oauth_codes WHERE did = ?", [did]),
        ("DELETE FROM invite_quotas WHERE did = ?", [did]),
        (
            """INSERT INTO takedowns (did, handle, actor, records_deleted, blobs_deleted, collections)
               VALUES (?, ?, ?, ?, ?, ?)""",
            [did, handle, actor, records_deleted, blobs_deleted, json.dumps(collections, separators=(",", ":"))],
        ),
    ])


async def update_account_handle(db, did: str, handle: str) -> None:
    await db.run("UPDATE accounts SET handle = ? WHERE did = ?", handle, did)


async def handle_owner(db, handle: str) -> str | None:
    row = await db.first("SELECT did FROM accounts WHERE handle = ? LIMIT 1", handle)
    return row["did"] if row else None


async def account_exists(db, did: str, handle: str) -> bool:
    return await db.first("SELECT 1 AS x FROM accounts WHERE did = ? OR handle = ? LIMIT 1", did, handle) is not None


def generate_invite_token() -> str:
    return "".join(
        INVITE_TOKEN_ALPHABET[byte % len(INVITE_TOKEN_ALPHABET)] for byte in secrets.token_bytes(INVITE_TOKEN_LENGTH)
    )


async def mint_rook_invite(db, did: str, quota: int) -> dict | None:
    token = generate_invite_token()
    changes = await db.run(
        "INSERT INTO invites (token, minted_by) SELECT ?, ? WHERE (SELECT COUNT(*) FROM invites WHERE minted_by = ?) < ?",
        token, did, did, quota,
    )
    if changes == 0:
        return None
    row = await db.first("SELECT COUNT(*) AS count FROM invites WHERE minted_by = ?", did)
    return {"token": token, "remaining": quota - (row["count"] if row else 0)}


async def mint_org_invite(db, idempotency_key: str | None = None) -> dict:
    # A retry with the same key returns the first mint instead of stranding another invite.
    if idempotency_key:
        existing = await db.first("SELECT token FROM invites WHERE idempotency_key = ?", idempotency_key)
        if existing:
            return {"token": existing["token"], "replayed": True}
    token = generate_invite_token()
    try:
        await db.run(
            "INSERT INTO invites (token, minted_by, idempotency_key) VALUES (?, 'org', ?)", token, idempotency_key
        )
    except Exception as exc:
        # Concurrent first use of a key: the unique index rejects the loser.
        if idempotency_key and "UNIQUE constraint failed" in str(exc):
            existing = await db.first("SELECT token FROM invites WHERE idempotency_key = ?", idempotency_key)
            if existing:
                return {"token": existing["token"], "replayed": True}
        raise
    return {"token": token, "replayed": False}


async def get_effective_quota(db, did: str) -> int:
    override = await db.first("SELECT quota FROM invite_quotas WHERE did = ?", did)
    if override:
        return override["quota"]
    row = await db.first("SELECT value FROM config WHERE key = 'invite_quota_default'")
    if not row:
        raise RuntimeError("invite_quota_default is missing")
    try:
        quota = int(row["value"])
    except ValueError:
        quota = -1
    if quota < 0 or str(quota) != str(row["value"]).strip():
        raise RuntimeError("invite_quota_default must be a non-negative integer")
    return quota


async def set_invite_quota(db, did: str, quota: int) -> None:
    await db.run(
        "INSERT INTO invite_quotas (did, quota) VALUES (?, ?) ON CONFLICT(did) DO UPDATE SET quota = excluded.quota",
        did, quota,
    )


async def set_invite_quota_default(db, value: int) -> None:
    await db.run(
        "INSERT INTO config (key, value, updated_at) VALUES ('invite_quota_default', ?, datetime('now')) "
        "ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = datetime('now')",
        str(value),
    )


async def list_invites(db, limit: int, cursor: dict | None = None, state: str | None = None) -> list[dict]:
    conditions, binds = [], []
    if cursor:
        conditions.append("(minted_at, token) < (?, ?)")
        binds += [cursor["minted_at"], cursor["token"]]
    # "unspent" also excludes in-flight invites (spent_by_did = 'pending').
    if state == "unspent":
        conditions.append("spent_by_did IS NULL")
    elif state == "spent":
        conditions.append("spent_by_did IS NOT NULL")
    where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
    return await db.all(
        f"SELECT token, minted_by, minted_at, spent_by_did, spent_at FROM invites {where} "
        "ORDER BY minted_at DESC, token DESC LIMIT ?",
        *binds, limit,
    )


async def revoke_invite(db, token: str) -> str:
    """Hard-delete an unspent invite: "revoked", "spent" (spent or in flight), or "not_found"."""
    if await db.run("DELETE FROM invites WHERE token = ? AND spent_by_did IS NULL", token) == 1:
        return "revoked"
    row = await db.first("SELECT 1 AS x FROM invites WHERE token = ? LIMIT 1", token)
    return "spent" if row else "not_found"


async def is_invite_available(db, token: str) -> bool:
    return await db.first("SELECT 1 AS x FROM invites WHERE token = ? AND spent_by_did IS NULL LIMIT 1", token) is not None


async def spend_invite_pending(db, token: str) -> bool:
    return await db.run(
        "UPDATE invites SET spent_by_did = 'pending', spent_at = datetime('now') WHERE token = ? AND spent_by_did IS NULL",
        token,
    ) == 1


async def finalize_invite_spend(db, token: str, did: str) -> bool:
    return await db.run(
        "UPDATE invites SET spent_by_did = ? WHERE token = ? AND spent_by_did = 'pending'", did, token
    ) == 1


async def unspend_invite(db, token: str, spent_by_did: str) -> bool:
    return await db.run(
        "UPDATE invites SET spent_by_did = NULL, spent_at = NULL WHERE token = ? AND spent_by_did = ?",
        token, spent_by_did,
    ) == 1
