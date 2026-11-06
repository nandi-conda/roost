# SPDX-License-Identifier: MIT
# Copyright (c) 2026 sol pbc

"""Per-account repo storage in the Account Durable Object's SQLite.

The schema is the one the TypeScript rookery created, unchanged, so accounts
it wrote keep working: blocks (repo blocks by CID), repo_state (one row: keys,
handle, head), collections, blobs (metadata; bytes live in R2).

`sql` is anything with `exec(query, *params) -> list[dict]`; BLOB columns
come back as bytes.
"""

SCHEMA = [
    """CREATE TABLE IF NOT EXISTS blocks (
        cid TEXT PRIMARY KEY,
        bytes BLOB NOT NULL,
        rev TEXT NOT NULL
      )""",
    "CREATE INDEX IF NOT EXISTS idx_blocks_rev ON blocks(rev)",
    """CREATE TABLE IF NOT EXISTS repo_state (
        id INTEGER PRIMARY KEY CHECK (id = 1),
        did TEXT,
        handle TEXT,
        signing_key_hex TEXT,
        signing_key_pub TEXT,
        rotation_key_hex TEXT,
        rotation_key_pub TEXT,
        jwk_thumbprint TEXT,
        root_cid TEXT,
        rev TEXT,
        prev_data_cid TEXT,
        active INTEGER NOT NULL DEFAULT 1,
        created_at TEXT NOT NULL DEFAULT (datetime('now'))
      )""",
    "INSERT INTO repo_state (id) VALUES (1) ON CONFLICT DO NOTHING",
    """CREATE TABLE IF NOT EXISTS collections (
        collection TEXT PRIMARY KEY
      )""",
    """CREATE TABLE IF NOT EXISTS blobs (
        cid TEXT PRIMARY KEY,
        mime_type TEXT NOT NULL,
        size INTEGER NOT NULL,
        created_at TEXT NOT NULL DEFAULT (datetime('now'))
      )""",
]

STATE_FIELDS = (
    "did", "handle", "signing_key_hex", "signing_key_pub", "rotation_key_hex",
    "rotation_key_pub", "jwk_thumbprint", "root_cid", "rev", "prev_data_cid",
    "active", "created_at",
)


class RepoStorage:
    def __init__(self, sql):
        self.sql = sql

    def init_schema(self) -> None:
        for statement in SCHEMA:
            self.sql.exec(statement)

    # Account state

    def init_account_state(self, *, did, handle, signing_key_hex, signing_key_pub,
                           rotation_key_hex, rotation_key_pub, jwk_thumbprint) -> None:
        self.sql.exec(
            """UPDATE repo_state SET did = ?, handle = ?, signing_key_hex = ?, signing_key_pub = ?,
               rotation_key_hex = ?, rotation_key_pub = ?, jwk_thumbprint = ? WHERE id = 1""",
            did, handle, signing_key_hex, signing_key_pub, rotation_key_hex,
            rotation_key_pub, jwk_thumbprint,
        )

    def get_state(self) -> dict | None:
        rows = self.sql.exec("SELECT * FROM repo_state WHERE id = 1")
        return rows[0] if rows else None

    def set_handle(self, handle: str) -> None:
        self.sql.exec("UPDATE repo_state SET handle = ? WHERE id = 1", handle)

    # Blocks (the synchronous block store the MST reads from)

    def get_block(self, cid) -> bytes | None:
        rows = self.sql.exec("SELECT bytes FROM blocks WHERE cid = ?", str(cid))
        return bytes(rows[0]["bytes"]) if rows else None

    def has_block(self, cid) -> bool:
        return bool(self.sql.exec("SELECT 1 AS x FROM blocks WHERE cid = ? LIMIT 1", str(cid)))

    def apply_commit(self, *, cid, rev: str, data_cid, new_blocks: dict, removed: set) -> None:
        """Store a commit's new blocks, drop the ones it removed, and move the head."""
        for block_cid, raw in new_blocks.items():
            self.sql.exec(
                "INSERT INTO blocks (cid, bytes, rev) VALUES (?, ?, ?) "
                "ON CONFLICT (cid) DO UPDATE SET bytes = excluded.bytes, rev = excluded.rev",
                str(block_cid), raw, rev,
            )
        for block_cid in removed:
            if block_cid not in new_blocks:
                self.sql.exec("DELETE FROM blocks WHERE cid = ?", str(block_cid))
        self.sql.exec(
            "UPDATE repo_state SET root_cid = ?, rev = ?, prev_data_cid = ? WHERE id = 1",
            str(cid), rev, str(data_cid),
        )

    def all_blocks(self) -> list[tuple[str, bytes]]:
        return [(row["cid"], bytes(row["bytes"])) for row in self.sql.exec("SELECT cid, bytes FROM blocks")]

    # Collections and blobs

    def add_collection(self, collection: str) -> None:
        self.sql.exec("INSERT INTO collections (collection) VALUES (?) ON CONFLICT DO NOTHING", collection)

    def get_collections(self) -> list[str]:
        return [row["collection"] for row in self.sql.exec("SELECT collection FROM collections ORDER BY collection")]

    def count_blocks(self) -> int:
        return self.sql.exec("SELECT COUNT(*) AS n FROM blocks")[0]["n"]

    def count_blobs(self) -> int:
        return self.sql.exec("SELECT COUNT(*) AS n FROM blobs")[0]["n"]

    def insert_blob(self, cid: str, mime_type: str, size: int) -> None:
        self.sql.exec(
            "INSERT INTO blobs (cid, mime_type, size) VALUES (?, ?, ?) ON CONFLICT DO NOTHING", cid, mime_type, size
        )

    def list_blobs(self, limit: int = 500, cursor: str | None = None) -> dict:
        if cursor:
            rows = self.sql.exec(
                "SELECT cid FROM blobs WHERE cid > ? ORDER BY cid ASC LIMIT ?", cursor, limit + 1
            )
        else:
            rows = self.sql.exec("SELECT cid FROM blobs ORDER BY cid ASC LIMIT ?", limit + 1)
        has_more = len(rows) > limit
        cids = [row["cid"] for row in rows[:limit]]
        result = {"cids": cids}
        if has_more:
            result["cursor"] = cids[-1]
        return result

    # Moving an account between hosts

    def dump(self) -> dict:
        state = self.get_state()
        if not state or not state.get("did"):
            raise ValueError("Account not provisioned")
        return {
            "state": state,
            "blocks": [
                {"cid": row["cid"], "bytes": bytes(row["bytes"]), "rev": row["rev"]}
                for row in self.sql.exec("SELECT cid, bytes, rev FROM blocks")
            ],
            "collections": self.get_collections(),
            "blobs": self.sql.exec("SELECT cid, mime_type, size, created_at FROM blobs"),
        }

    def restore(self, dump: dict) -> None:
        current = self.get_state()
        if current and current.get("did"):
            raise ValueError("Account already provisioned")
        state = dump["state"]
        self.sql.exec(
            """UPDATE repo_state SET did = ?, handle = ?, signing_key_hex = ?, signing_key_pub = ?,
               rotation_key_hex = ?, rotation_key_pub = ?, jwk_thumbprint = ?, root_cid = ?, rev = ?,
               prev_data_cid = ?, active = ?, created_at = ? WHERE id = 1""",
            *(state.get(field) for field in STATE_FIELDS),
        )
        for block in dump["blocks"]:
            self.sql.exec(
                "INSERT INTO blocks (cid, bytes, rev) VALUES (?, ?, ?)",
                block["cid"], bytes(block["bytes"]), block["rev"],
            )
        for collection in dump["collections"]:
            self.add_collection(collection)
        for blob in dump["blobs"]:
            self.sql.exec(
                "INSERT INTO blobs (cid, mime_type, size, created_at) VALUES (?, ?, ?, ?)",
                blob["cid"], blob["mime_type"], blob["size"], blob["created_at"],
            )

    def delete_all(self) -> None:
        for table in ("blocks", "collections", "blobs", "repo_state"):
            self.sql.exec(f"DELETE FROM {table}")
