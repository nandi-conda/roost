# SPDX-License-Identifier: MIT
# Copyright (c) 2026 sol pbc

"""Space storage in an account's Durable Object SQLite, as the space reader and
transactor in the reference PDS.

Every account holds its own repos in other spaces (space, space_repo,
space_record, space_record_oplog, space_record_blob). An account that is a space
authority also holds that space's governance: space_policy (the policy as
normalized JSON), memberspace_member, space_writer (the sequenced writer set) and
space_credential_recipient (services registered for write notifications), and
the deletion notices it still owes them. space_kem_key holds the account's
#atproto_kem key, which keys the MACs on its space repos.

space_writer.hash and space_notification_retry.hash hold what the wire now calls
`data` (the sha256 of the LtHash state); the stored values are unchanged.
"""

import json
from datetime import datetime, timedelta, timezone

from .. import cbor
from ..cbor import CID
from ..errors import XrpcError
from ..lexjson import lex_to_json
from ..tid import next_tid
from .commit import apply_op, build_commit
from .lthash import LtHash
from .policy import MANAGEDSPACE, MEMBERSPACE
from .refs import SpaceRef
from .star import write_repo_star

SCHEMA = [
    """CREATE TABLE IF NOT EXISTS space (
        uri TEXT PRIMARY KEY,
        authority TEXT NOT NULL,
        type TEXT NOT NULL,
        created_at TEXT NOT NULL,
        deleted_at TEXT
      )""",
    """CREATE TABLE IF NOT EXISTS space_policy (
        uri TEXT PRIMARY KEY,
        policy_json TEXT NOT NULL
      )""",
    """CREATE TABLE IF NOT EXISTS memberspace_member (
        space TEXT NOT NULL,
        did TEXT NOT NULL,
        can_read INTEGER NOT NULL,
        can_write INTEGER NOT NULL,
        PRIMARY KEY (space, did)
      )""",
    """CREATE TABLE IF NOT EXISTS space_record (
        uri TEXT PRIMARY KEY,
        space TEXT NOT NULL,
        collection TEXT NOT NULL,
        rkey TEXT NOT NULL,
        cid TEXT NOT NULL,
        value BLOB NOT NULL,
        repo_rev TEXT NOT NULL,
        indexed_at TEXT NOT NULL
      )""",
    "CREATE UNIQUE INDEX IF NOT EXISTS space_record_path_idx ON space_record(space, collection, rkey)",
    "CREATE INDEX IF NOT EXISTS space_record_rev_idx ON space_record(space, repo_rev)",
    """CREATE TABLE IF NOT EXISTS space_record_blob (
        blob_cid TEXT NOT NULL,
        record_uri TEXT NOT NULL,
        PRIMARY KEY (blob_cid, record_uri)
      )""",
    "CREATE INDEX IF NOT EXISTS space_record_blob_record_idx ON space_record_blob(record_uri)",
    """CREATE TABLE IF NOT EXISTS space_repo (
        space TEXT PRIMARY KEY,
        set_hash BLOB,
        rev TEXT
      )""",
    """CREATE TABLE IF NOT EXISTS space_record_oplog (
        space TEXT NOT NULL,
        rev TEXT NOT NULL,
        idx INTEGER NOT NULL,
        action TEXT NOT NULL,
        uri TEXT NOT NULL,
        collection TEXT NOT NULL,
        rkey TEXT NOT NULL,
        cid TEXT,
        prev TEXT,
        PRIMARY KEY (space, rev, idx)
      )""",
    """CREATE TABLE IF NOT EXISTS space_writer (
        space TEXT NOT NULL,
        did TEXT NOT NULL,
        repo_rev TEXT NOT NULL,
        hash BLOB NOT NULL,
        space_rev TEXT NOT NULL,
        PRIMARY KEY (space, did)
      )""",
    "CREATE INDEX IF NOT EXISTS space_writer_space_rev_idx ON space_writer(space, space_rev)",
    """CREATE TABLE IF NOT EXISTS space_credential_recipient (
        space TEXT NOT NULL,
        service_did TEXT NOT NULL,
        service_endpoint TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        PRIMARY KEY (space, service_did)
      )""",
    # Write notifications this account still owes a space host (newest rev per space).
    """CREATE TABLE IF NOT EXISTS space_notification_retry (
        space TEXT PRIMARY KEY,
        repo_rev TEXT NOT NULL,
        hash BLOB NOT NULL,
        attempts INTEGER NOT NULL,
        retry_at INTEGER NOT NULL,
        expires_at INTEGER NOT NULL
      )""",
    # notifySpaceDeleted owed to syncers registered when a space was deleted, until
    # delivered or their registration expires.
    """CREATE TABLE IF NOT EXISTS space_deleted_notification_retry (
        space TEXT NOT NULL,
        service_did TEXT NOT NULL,
        attempts INTEGER NOT NULL,
        retry_at INTEGER NOT NULL,
        expires_at INTEGER NOT NULL,
        PRIMARY KEY (space, service_did)
      )""",
    """CREATE TABLE IF NOT EXISTS space_kem_key (
        id INTEGER PRIMARY KEY CHECK (id = 1),
        private_key_hex TEXT NOT NULL
      )""",
]

REGISTRATION_TTL = timedelta(days=1)


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def space_not_found() -> XrpcError:
    return XrpcError("SpaceNotFound", "Space not found")


def simplespace_config_to_policy(config: dict) -> dict:
    """An October 22 simplespace_config row as its October 29 policy, as the reference
    PDS's 006-space-policy migration: a managing app on either side makes a
    managedspace (asked about both reads and writes, any allow-list dropped);
    anything else is a memberspace."""
    managing_app = config["read_managing_app"] or config["write_managing_app"]
    if managing_app:
        return {"$type": MANAGEDSPACE, "managingApp": managing_app, "publishPolicy": False}
    policy = {"$type": MEMBERSPACE, "publicRead": config["read_policy"] == "public",
              "publicWrite": config["write_policy"] == "public"}
    if config["app_access_type"] == "allowList":
        policy["allowedApps"] = json.loads(config["app_allowed"])
    return dict(policy, publishPolicy=False, publishMembers=False)


def find_blob_refs(value) -> list[tuple[str, str | None]]:
    """(cid, mimeType) for every blob ref in a lex value."""
    found = []
    if isinstance(value, dict):
        ref = value.get("ref")
        if value.get("$type") == "blob" and isinstance(ref, CID):
            found.append((str(ref), value.get("mimeType")))
        for item in value.values():
            found.extend(find_blob_refs(item))
    elif isinstance(value, list):
        for item in value:
            found.extend(find_blob_refs(item))
    return found


class SpaceStore:
    """`sql.exec(query, *params) -> list[dict]`, synchronous, inside the DO."""

    def __init__(self, sql):
        self.sql = sql

    def init_schema(self) -> None:
        for statement in SCHEMA:
            self.sql.exec(statement)
        self._migrate_simplespace()

    def _migrate_simplespace(self) -> None:
        """Convert October 22 simplespace configs to policies, once; drop member lists
        of spaces that become managedspace."""
        if not self._one("SELECT 1 AS x FROM sqlite_master WHERE type = 'table' AND name = 'simplespace_config'"):
            return
        for config in self.sql.exec("SELECT * FROM simplespace_config"):
            policy = simplespace_config_to_policy(config)
            self.sql.exec("INSERT OR REPLACE INTO space_policy (uri, policy_json) VALUES (?, ?)",
                          config["uri"], json.dumps(policy))
            if policy["$type"] == MEMBERSPACE:
                self.sql.exec(
                    """INSERT OR REPLACE INTO memberspace_member (space, did, can_read, can_write)
                       SELECT space, did, can_read, can_write FROM simplespace_member WHERE space = ?""",
                    config["uri"],
                )
        self.sql.exec("DROP TABLE IF EXISTS simplespace_member")
        self.sql.exec("DROP TABLE simplespace_config")

    def _one(self, query: str, *params) -> dict | None:
        rows = self.sql.exec(query, *params)
        return rows[0] if rows else None

    # Spaces

    def get_space(self, uri: str) -> dict | None:
        return self._one("SELECT * FROM space WHERE uri = ?", uri)

    def get_policy(self, uri: str) -> dict | None:
        row = self._one("SELECT policy_json FROM space_policy WHERE uri = ?", uri)
        return json.loads(row["policy_json"]) if row else None

    def get_active_policy(self, uri: str) -> dict:
        space, policy = self.get_space(uri), self.get_policy(uri)
        if not space or space["deleted_at"] or not policy:
            raise space_not_found()
        return policy

    def ensure_space(self, uri: str) -> None:
        ref = SpaceRef.parse(uri)
        self.sql.exec(
            """INSERT INTO space (uri, authority, type, created_at, deleted_at) VALUES (?, ?, ?, ?, NULL)
               ON CONFLICT (uri) DO UPDATE SET deleted_at = NULL""",
            uri, ref.did, ref.type, now_iso(),
        )
        self.sql.exec("INSERT OR IGNORE INTO space_repo (space, set_hash, rev) VALUES (?, NULL, NULL)", uri)

    def create_space(self, uri: str, policy: dict) -> None:
        if self.get_policy(uri):
            raise XrpcError("SpaceAlreadyExists", "Space already exists")
        # A recreated space is a new space: deletion notices still owed for the old
        # one would purge the syncers' copies of the new one.
        self.sql.exec("DELETE FROM space_deleted_notification_retry WHERE space = ?", uri)
        self.ensure_space(uri)
        self.set_policy(uri, policy)

    def set_policy(self, uri: str, policy: dict) -> None:
        self.sql.exec("INSERT OR REPLACE INTO space_policy (uri, policy_json) VALUES (?, ?)", uri, json.dumps(policy))

    def delete_space(self, uri: str) -> list[dict]:
        """Tombstone a space this account governs and drop its own repo there; returns the
        registered services owed a notice ({service_did, expires_at}). Members' repos stay
        on their hosts. Deleting a deleted space does nothing."""
        existing = self.get_space(uri)
        if not existing:
            raise space_not_found()
        if existing["deleted_at"]:
            return []
        recipients = self.get_recipients(uri)
        self.sql.exec("UPDATE space SET deleted_at = ? WHERE uri = ?", now_iso(), uri)
        self.sql.exec(
            "DELETE FROM space_record_blob WHERE record_uri IN (SELECT uri FROM space_record WHERE space = ?)", uri
        )
        self.sql.exec("DELETE FROM space_policy WHERE uri = ?", uri)
        for table in ("memberspace_member", "space_writer", "space_credential_recipient", "space_record",
                      "space_record_oplog", "space_repo", "space_notification_retry"):
            self.sql.exec(f"DELETE FROM {table} WHERE space = ?", uri)
        return [{"service_did": row["service_did"], "expires_at": row["expires_at"]} for row in recipients]

    def list_spaces(self, limit: int, cursor: str | None, space_type: str | None, authority: str | None) -> list[str]:
        query, params = "SELECT uri FROM space WHERE deleted_at IS NULL", []
        if authority:
            query += " AND authority = ?"
            params.append(authority)
        if space_type:
            query += " AND type = ?"
            params.append(space_type)
        if cursor:
            query += " AND uri > ?"
            params.append(cursor)
        query += " ORDER BY uri ASC LIMIT ?"
        return [row["uri"] for row in self.sql.exec(query, *params, limit)]

    # Members (memberspace)

    def get_member(self, space: str, did: str) -> dict | None:
        row = self._one("SELECT can_read, can_write FROM memberspace_member WHERE space = ? AND did = ?", space, did)
        return {"read": bool(row["can_read"]), "write": bool(row["can_write"])} if row else None

    def put_member(self, space: str, did: str, read: bool, write: bool) -> None:
        self.sql.exec(
            """INSERT INTO memberspace_member (space, did, can_read, can_write) VALUES (?, ?, ?, ?)
               ON CONFLICT (space, did) DO UPDATE SET can_read = excluded.can_read, can_write = excluded.can_write""",
            space, did, 1 if read else 0, 1 if write else 0,
        )

    def remove_member(self, space: str, did: str) -> None:
        self.sql.exec("DELETE FROM memberspace_member WHERE space = ? AND did = ?", space, did)

    def remove_all_members(self, space: str) -> None:
        self.sql.exec("DELETE FROM memberspace_member WHERE space = ?", space)

    def list_members(self, space: str, limit: int | None = None, cursor: str | None = None) -> list[dict]:
        query, params = "SELECT did, can_read, can_write FROM memberspace_member WHERE space = ?", [space]
        if cursor:
            query += " AND did > ?"
            params.append(cursor)
        query += " ORDER BY did ASC"
        if limit is not None:
            query += " LIMIT ?"
            params.append(limit)
        rows = self.sql.exec(query, *params)
        return [{"did": row["did"], "read": bool(row["can_read"]), "write": bool(row["can_write"])} for row in rows]

    # The writer set (space host)

    def record_writer(self, space: str, did: str, repo_rev: str, digest: bytes) -> dict | None:
        """Note a newer repo state and advance the space sequence; None when not newer."""
        current = self.get_space(space)
        if not current or current["deleted_at"]:
            raise space_not_found()
        writer = self._one("SELECT repo_rev FROM space_writer WHERE space = ? AND did = ?", space, did)
        if writer and writer["repo_rev"] >= repo_rev:
            return None
        latest = self._one(
            "SELECT space_rev FROM space_writer WHERE space = ? ORDER BY space_rev DESC LIMIT 1", space
        )
        prev_space_rev = latest["space_rev"] if latest else None
        space_rev = next_tid(prev_space_rev)
        self.sql.exec(
            """INSERT INTO space_writer (space, did, repo_rev, hash, space_rev) VALUES (?, ?, ?, ?, ?)
               ON CONFLICT (space, did) DO UPDATE SET repo_rev = excluded.repo_rev, hash = excluded.hash,
               space_rev = excluded.space_rev""",
            space, did, repo_rev, digest, space_rev,
        )
        sequence = {"spaceRev": space_rev}
        if prev_space_rev:
            sequence["prevSpaceRev"] = prev_space_rev
        return sequence

    def remove_writer(self, space: str, did: str) -> None:
        self.sql.exec("DELETE FROM space_writer WHERE space = ? AND did = ?", space, did)

    def list_writers(self, space: str, limit: int | None, cursor: str | None) -> list[dict]:
        self.get_active_policy(space)
        query, params = "SELECT did, repo_rev, hash, space_rev FROM space_writer WHERE space = ?", [space]
        if cursor:
            query += " AND space_rev > ?"
            params.append(cursor)
        query += " ORDER BY space_rev ASC"
        if limit is not None:
            query += " LIMIT ?"
            params.append(limit)
        rows = self.sql.exec(query, *params)
        return [{"did": r["did"], "repoRev": r["repo_rev"], "data": bytes(r["hash"]), "spaceRev": r["space_rev"]}
                for r in rows]

    # Notification recipients (space host)

    def register_recipient(self, space: str, service_did: str, endpoint: str) -> str:
        self.get_active_policy(space)
        expires = (datetime.now(timezone.utc) + REGISTRATION_TTL).isoformat(timespec="milliseconds")
        expires = expires.replace("+00:00", "Z")
        self.sql.exec(
            """INSERT INTO space_credential_recipient (space, service_did, service_endpoint, expires_at)
               VALUES (?, ?, ?, ?) ON CONFLICT (space, service_did) DO UPDATE SET
               service_endpoint = excluded.service_endpoint, expires_at = excluded.expires_at""",
            space, service_did, endpoint, expires,
        )
        return expires

    def unregister_recipient(self, space: str, service_did: str) -> None:
        self.get_active_policy(space)
        self.sql.exec("DELETE FROM space_credential_recipient WHERE space = ? AND service_did = ?", space, service_did)

    def get_recipients(self, space: str) -> list[dict]:
        return self.sql.exec(
            """SELECT service_did, service_endpoint, expires_at FROM space_credential_recipient
               WHERE space = ? AND expires_at > ?""",
            space, now_iso(),
        )

    # This account's own repo in a space

    def get_repo_state(self, space: str) -> dict | None:
        return self._one("SELECT set_hash, rev FROM space_repo WHERE space = ?", space)

    def _record_cid(self, uri: str) -> str | None:
        row = self._one("SELECT cid FROM space_record WHERE uri = ?", uri)
        return row["cid"] if row else None

    def has_record(self, uri: str) -> bool:
        return self._record_cid(uri) is not None

    def apply_writes(self, did: str, space: str, writes: list[dict], known_blobs) -> dict | None:
        """Apply prepared writes ({action, collection, rkey, uri, cid?, value?}) as one commit.
        `known_blobs(cid) -> bool` says whether the account uploaded a blob. Returns
        {rev, set_hash} or None for an empty batch."""
        if not writes:
            return None
        self._ensure_own_repo(did, space)
        state = self.get_repo_state(space)
        set_hash = LtHash(bytes(state["set_hash"]) if state and state["set_hash"] else None)
        rev = next_tid(state["rev"] if state else None)
        indexed_at = now_iso()
        for idx, write in enumerate(writes):
            uri, collection, rkey = write["uri"], write["collection"], write["rkey"]
            prev = self._record_cid(uri)
            cid = None
            if write["action"] == "delete":
                if not prev:
                    raise XrpcError("RecordNotFound", f"Record not found: {collection}/{rkey}")
                self.sql.exec("DELETE FROM space_record WHERE uri = ?", uri)
                self.sql.exec("DELETE FROM space_record_blob WHERE record_uri = ?", uri)
            else:
                if write["action"] == "create" and prev:
                    raise XrpcError("RecordAlreadyExists", f"Record already exists: {collection}/{rkey}")
                if write["action"] == "update" and not prev:
                    raise XrpcError("RecordNotFound", f"Record not found: {collection}/{rkey}")
                cid = write["cid"]
                self.sql.exec(
                    """INSERT INTO space_record (uri, space, collection, rkey, cid, value, repo_rev, indexed_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT (uri) DO UPDATE SET cid = excluded.cid,
                       value = excluded.value, repo_rev = excluded.repo_rev, indexed_at = excluded.indexed_at""",
                    uri, space, collection, rkey, cid, write["value"], rev, indexed_at,
                )
                self.sql.exec("DELETE FROM space_record_blob WHERE record_uri = ?", uri)
                for blob_cid, _ in find_blob_refs(cbor.decode(write["value"])):
                    if not known_blobs(blob_cid):
                        raise XrpcError("BlobNotFound", f"Could not find blob: {blob_cid}")
                    self.sql.exec(
                        "INSERT OR IGNORE INTO space_record_blob (blob_cid, record_uri) VALUES (?, ?)", blob_cid, uri
                    )
            apply_op(set_hash, collection, rkey, cid, prev)
            self.sql.exec(
                """INSERT INTO space_record_oplog (space, rev, idx, action, uri, collection, rkey, cid, prev)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                space, rev, idx, write["action"], uri, collection, rkey, cid, prev,
            )
        state_bytes = set_hash.state()
        self.sql.exec("UPDATE space_repo SET set_hash = ?, rev = ? WHERE space = ?", state_bytes, rev, space)
        return {"rev": rev, "set_hash": state_bytes}

    def list_collections(self, space: str) -> list[str]:
        return [row["collection"] for row in
                self.sql.exec("SELECT DISTINCT collection FROM space_record WHERE space = ?", space)]

    def _ensure_own_repo(self, did: str, space: str) -> None:
        """A repo in the account's own space needs the space; any other is created on demand."""
        if SpaceRef.parse(space).did == did:
            existing = self.get_space(space)
            if not existing or existing["deleted_at"]:
                raise space_not_found()
        self.ensure_space(space)

    def _set_repo_from_records(self, space: str, rev: str) -> dict:
        set_hash = LtHash()
        for row in self.sql.exec("SELECT collection, rkey, cid FROM space_record WHERE space = ?", space):
            apply_op(set_hash, row["collection"], row["rkey"], row["cid"], None)
        state_bytes = set_hash.state()
        self.sql.exec("UPDATE space_repo SET set_hash = ?, rev = ? WHERE space = ?", state_bytes, rev, space)
        return {"rev": rev, "set_hash": state_bytes}

    def clear_records(self, space: str, keep: tuple[str, ...]) -> dict | None:
        """Delete every record outside `keep` and the oplog, at a new rev; None when there
        was nothing to delete."""
        state = self.get_repo_state(space)
        if not state:
            return None
        marks = ",".join("?" * len(keep))
        where = f"space = ? AND collection NOT IN ({marks})" if keep else "space = ?"
        doomed = self.sql.exec(f"SELECT uri FROM space_record WHERE {where}", space, *keep)
        if not doomed:
            return None
        self.sql.exec(f"DELETE FROM space_record_blob WHERE record_uri IN (SELECT uri FROM space_record WHERE {where})",
                      space, *keep)
        self.sql.exec(f"DELETE FROM space_record WHERE {where}", space, *keep)
        self.sql.exec("DELETE FROM space_record_oplog WHERE space = ?", space)
        return self._set_repo_from_records(space, next_tid(state["rev"]))

    def import_repo(self, did: str, space: str, records: list[tuple[str, str, str, bytes]]) -> dict:
        """Replace the account's repo in `space` with (collection, rkey, cid, value)
        records already checked against their CIDs, at a new rev and no history."""
        self._ensure_own_repo(did, space)
        self.sql.exec(
            "DELETE FROM space_record_blob WHERE record_uri IN (SELECT uri FROM space_record WHERE space = ?)", space
        )
        self.sql.exec("DELETE FROM space_record WHERE space = ?", space)
        self.sql.exec("DELETE FROM space_record_oplog WHERE space = ?", space)
        state = self.get_repo_state(space)
        rev = next_tid(state["rev"] if state else None)
        ref, indexed_at = SpaceRef.parse(space), now_iso()
        for collection, rkey, cid, value in records:
            uri = ref.record_uri(did, collection, rkey)
            self.sql.exec(
                """INSERT INTO space_record (uri, space, collection, rkey, cid, value, repo_rev, indexed_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                uri, space, collection, rkey, cid, value, rev, indexed_at,
            )
            # Blobs are uploaded after the import, so they are associated unchecked.
            for blob_cid, _ in find_blob_refs(cbor.decode(value)):
                self.sql.exec("INSERT OR IGNORE INTO space_record_blob (blob_cid, record_uri) VALUES (?, ?)",
                              blob_cid, uri)
        return self._set_repo_from_records(space, rev)

    def import_space(self, uri: str, policy: dict, members: list[dict], writers: list[dict]) -> None:
        """Replace the policy, member list and writer set of a space (a migration's
        importSpaceMeta); revives a tombstone, since the archive is the newer truth."""
        self.ensure_space(uri)
        self.set_policy(uri, policy)
        self.remove_all_members(uri)
        for member in members:
            self.put_member(uri, member["did"], member["read"], member["write"])
        self.sql.exec("DELETE FROM space_writer WHERE space = ?", uri)
        for writer in writers:
            self.sql.exec("INSERT INTO space_writer (space, did, repo_rev, hash, space_rev) VALUES (?, ?, ?, ?, ?)",
                          uri, writer["did"], writer["rev"], writer["data"], writer["spaceRev"])

    def commit(self, space: str, repo: str) -> dict | None:
        """The repo's current commit; None when it has never been written to."""
        state = self.get_repo_state(space)
        if not state or not state["set_hash"] or not state["rev"]:
            return None
        return build_commit(bytes(state["set_hash"]), space, repo, state["rev"])

    def get_record(self, uri: str) -> dict | None:
        row = self._one("SELECT cid, value FROM space_record WHERE uri = ?", uri)
        if not row:
            return None
        return {"cid": row["cid"], "value": lex_to_json(cbor.decode(bytes(row["value"])))}

    def list_records(self, space: str, limit: int, cursor: str | None, reverse: bool,
                     collection: str | None, exclude_values: bool) -> list[dict]:
        query, params = "SELECT uri, collection, rkey, cid, value FROM space_record WHERE space = ?", [space]
        if collection:
            query += " AND collection = ?"
            params.append(collection)
        if cursor:
            query += " AND uri > ?" if reverse else " AND uri < ?"
            params.append(cursor)
        query += f" ORDER BY uri {'ASC' if reverse else 'DESC'} LIMIT ?"
        out = []
        for row in self.sql.exec(query, *params, limit):
            record = {"uri": row["uri"], "collection": row["collection"], "rkey": row["rkey"], "cid": row["cid"]}
            if not exclude_values:
                record["value"] = lex_to_json(cbor.decode(bytes(row["value"])))
            out.append(record)
        return out

    def list_repo_ops(self, space: str, limit: int, since: str | None, cursor: tuple[str, int] | None,
                      exclude_values: bool) -> list[dict]:
        # Joining on cid as well as uri serves only a record's current value.
        query = """SELECT o.rev, o.idx, o.collection, o.rkey, o.cid, o.prev, r.value FROM space_record_oplog o
                   LEFT JOIN space_record r ON r.uri = o.uri AND r.cid = o.cid WHERE o.space = ?"""
        params = [space]
        if since:
            query += " AND o.rev > ?"
            params.append(since)
        if cursor:
            query += " AND (o.rev > ? OR (o.rev = ? AND o.idx > ?))"
            params += [cursor[0], cursor[0], cursor[1]]
        rows = self.sql.exec(query + " ORDER BY o.rev ASC, o.idx ASC LIMIT ?", *params, limit)
        out = []
        for row in rows:
            op = {k: row[k] for k in ("rev", "idx", "collection", "rkey", "cid", "prev")}
            if not exclude_values and row["value"] is not None:
                op["value"] = lex_to_json(cbor.decode(bytes(row["value"])))
            out.append(op)
        return out

    def export_star(self, space: str, commit: dict) -> bytes:
        """The repo as a STAR archive: the commit, then records in byte order of their path."""
        rows = self.sql.exec("SELECT collection, rkey, value FROM space_record WHERE space = ?", space)
        records = sorted(((f"{row['collection']}/{row['rkey']}", bytes(row["value"])) for row in rows),
                         key=lambda record: record[0].encode())
        return write_repo_star(commit, records)

    def list_blobs(self, space: str, limit: int, since: str | None, cursor: str | None) -> list[str]:
        query = """SELECT DISTINCT b.blob_cid FROM space_record_blob b JOIN space_record r ON r.uri = b.record_uri
                   WHERE r.space = ?"""
        params = [space]
        if since:
            query += " AND r.repo_rev > ?"
            params.append(since)
        if cursor:
            query += " AND b.blob_cid > ?"
            params.append(cursor)
        return [row["blob_cid"] for row in self.sql.exec(query + " ORDER BY b.blob_cid ASC LIMIT ?", *params, limit)]

    def is_blob_in_space(self, space: str, blob_cid: str) -> bool:
        return self._one(
            """SELECT 1 AS x FROM space_record_blob b JOIN space_record r ON r.uri = b.record_uri
               WHERE r.space = ? AND b.blob_cid = ? LIMIT 1""", space, blob_cid,
        ) is not None

    # Write notifications this account owes

    def queue_notification(self, space: str, repo_rev: str, digest: bytes, attempts: int, retry_at: int,
                           expires_at: int) -> None:
        self.sql.exec(
            """INSERT INTO space_notification_retry (space, repo_rev, hash, attempts, retry_at, expires_at)
               VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT (space) DO UPDATE SET repo_rev = excluded.repo_rev,
               hash = excluded.hash, attempts = excluded.attempts, retry_at = excluded.retry_at,
               expires_at = excluded.expires_at WHERE excluded.repo_rev >= space_notification_retry.repo_rev""",
            space, repo_rev, digest, attempts, retry_at, expires_at,
        )

    def clear_notification(self, space: str, repo_rev: str) -> None:
        self.sql.exec("DELETE FROM space_notification_retry WHERE space = ? AND repo_rev <= ?", space, repo_rev)

    def due_notifications(self, now_ms: int) -> list[dict]:
        self.sql.exec("DELETE FROM space_notification_retry WHERE expires_at <= ?", now_ms)
        return self.sql.exec(
            "SELECT * FROM space_notification_retry WHERE retry_at <= ? ORDER BY retry_at LIMIT 5", now_ms
        )

    # Deletion notices this account (as authority) owes syncers

    def queue_deletion_notice(self, space: str, service_did: str, attempts: int, retry_at: int,
                              expires_at: int) -> None:
        self.sql.exec(
            """INSERT INTO space_deleted_notification_retry (space, service_did, attempts, retry_at, expires_at)
               VALUES (?, ?, ?, ?, ?) ON CONFLICT (space, service_did) DO UPDATE SET attempts = excluded.attempts,
               retry_at = excluded.retry_at, expires_at = excluded.expires_at""",
            space, service_did, attempts, retry_at, expires_at,
        )

    def clear_deletion_notice(self, space: str, service_did: str) -> None:
        self.sql.exec("DELETE FROM space_deleted_notification_retry WHERE space = ? AND service_did = ?",
                      space, service_did)

    def due_deletion_notices(self, now_ms: int) -> list[dict]:
        self.sql.exec("DELETE FROM space_deleted_notification_retry WHERE expires_at <= ?", now_ms)
        return self.sql.exec(
            "SELECT * FROM space_deleted_notification_retry WHERE retry_at <= ? ORDER BY retry_at LIMIT 5", now_ms
        )

    # The account's #atproto_kem key

    def kem_key_hex(self) -> str | None:
        row = self._one("SELECT private_key_hex FROM space_kem_key WHERE id = 1")
        return row["private_key_hex"] if row else None

    def set_kem_key_hex(self, private_key_hex: str) -> None:
        self.sql.exec("INSERT OR IGNORE INTO space_kem_key (id, private_key_hex) VALUES (1, ?)", private_key_hex)

