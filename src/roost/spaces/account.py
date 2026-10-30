# SPDX-License-Identifier: MIT
# Copyright (c) 2026 sol pbc

"""The Account Durable Object's space methods, mixed into Account.

Space data for an account lives in that account's own DO, beside its public
repo, and its keys never leave: space tokens are signed and commit and record
MACs computed here.
"""

import time

from .. import cbor
from ..cbor import CID
from ..errors import XrpcError
from ..keys import P256Keypair
from ..lexjson import json_to_lex
from ..syntax import is_valid_nsid, is_valid_record_key
from ..tid import next_tid
from .lthash import LtHash
from .mac import SpaceMacError, compute_commit_mac, compute_record_mac, decapsulate
from .meta import serialize_space_meta
from .policy import (
    MEMBERSPACE,
    PUBLISHED_COLLECTIONS,
    are_members_published,
    assert_memberspace,
    member_record_write,
    normalize_policy,
    policy_record_write,
)
from .refs import InvalidSpaceRef, SpaceRef
from .star import MAX_RECORD_SIZE
from .store import SpaceStore
from .tokens import build_token

MAX_WRITES = 200
WRITE_TYPES = {
    "com.atproto.space.applyWrites#create": "create",
    "com.atproto.space.applyWrites#update": "update",
    "com.atproto.space.applyWrites#delete": "delete",
}

SPACE_METHODS = frozenset({
    "space_create", "space_update", "space_get", "space_status", "space_delete", "space_put_member",
    "space_remove_member", "space_list_members", "space_get_member", "space_remove_writer", "space_export_meta",
    "space_import_meta", "space_list_collections", "space_clear_records", "space_import_repo", "space_record_writer",
    "space_list_writers", "space_register_recipient", "space_unregister_recipient", "space_recipients",
    "space_apply_writes", "space_put_record", "space_get_record", "space_list_records", "space_list_repo_ops",
    "space_latest_commit", "space_export_star", "space_list_blobs", "space_has_blob", "space_list_spaces",
    "space_sign_token", "space_signing_key", "space_kem_key", "space_queue_notification",
    "space_clear_notification", "space_due_notifications", "space_queue_deletion_notice",
    "space_clear_deletion_notice", "space_due_deletion_notices",
})


def parse_space(space) -> SpaceRef:
    try:
        return SpaceRef.parse(space)
    except InvalidSpaceRef as exc:
        raise XrpcError("InvalidRequest", str(exc)) from exc


def prepare_write(did: str, ref: SpaceRef, action: str, collection, rkey, record=None) -> dict:
    """{action, collection, rkey, uri, cid?, value?}: a write validated and encoded."""
    if not is_valid_nsid(collection):
        raise XrpcError("InvalidRequest", f"Invalid collection: {collection}")
    if rkey is None and action == "create":
        rkey = next_tid()
    if not is_valid_record_key(rkey):
        raise XrpcError("InvalidRequest", f"Invalid record key: {rkey}")
    write = {"action": action, "collection": collection, "rkey": rkey,
             "uri": ref.record_uri(did, collection, rkey)}
    if action == "delete":
        return write
    if not isinstance(record, dict):
        raise XrpcError("InvalidRecord", "Record must be an object")
    record_type = record.get("$type", collection)
    if record_type != collection:
        raise XrpcError("InvalidRecord", f"Record $type {record_type} does not match collection {collection}")
    lex = json_to_lex(dict(record, **{"$type": collection}))
    try:
        value = cbor.encode(lex)
    except cbor.CborError as exc:
        raise XrpcError("InvalidRecord", f"Invalid record: {exc}") from exc
    if len(value) > MAX_RECORD_SIZE:
        raise XrpcError("InvalidRecord", f"Record exceeds {MAX_RECORD_SIZE} bytes")
    return dict(write, cid=str(CID.for_cbor(value)), value=value)


def write_result(write: dict) -> dict:
    if write["action"] == "delete":
        return {"$type": "com.atproto.space.applyWrites#deleteResult"}
    return {
        "$type": f"com.atproto.space.applyWrites#{write['action']}Result",
        "uri": write["uri"], "cid": write["cid"], "validationStatus": "unknown",
    }


class SpaceMethods:
    """Needs self.storage (RepoStorage, for its sql and blobs), self._state() and self._keypair()."""

    @property
    def spaces(self) -> SpaceStore:
        store = getattr(self, "_spaces", None)
        if store is None:
            store = self._spaces = SpaceStore(self.storage.sql)
        return store

    def _did(self) -> str:
        return self._state()["did"]

    def _commit_out(self, commit: dict | None) -> dict | None:
        if commit is None:
            return None
        return {"rev": commit["rev"], "data": LtHash(commit["set_hash"]).digest()}

    def _mac_secret(self, key_share: str | None) -> bytes | None:
        """The shared secret for a requested MAC (None when none was requested)."""
        if key_share is None:
            return None
        private_key_hex = self.spaces.kem_key_hex()
        if not private_key_hex:
            raise XrpcError("BadSpaceMac", "Account has no #atproto_kem key yet")
        try:
            return decapsulate(P256Keypair.import_hex(private_key_hex), key_share)
        except SpaceMacError as exc:
            raise XrpcError("BadSpaceMac", str(exc)) from exc

    def _commit_with_mac(self, space: str, key_share: str | None) -> dict | None:
        commit = self.spaces.commit(space, self._did())
        if commit is None:
            return None
        secret = self._mac_secret(key_share)
        return {"commit": commit, "mac": compute_commit_mac(secret, commit) if secret else None}

    def _known_blob(self, cid: str) -> bool:
        return bool(self.storage.sql.exec("SELECT 1 AS x FROM blobs WHERE cid = ? LIMIT 1", cid))

    # Governance (this account is the space authority). A change that publishes the
    # space's configuration returns the commit to the authority's repo, owed a notifyWrite.

    def _publish(self, space: str, writes: list[tuple[str, str, dict | None]]) -> dict | None:
        """Bring published records ((collection, rkey, record or None)) in line, as one commit."""
        did, ref = self._did(), parse_space(space)
        prepared = []
        for collection, rkey, record in writes:
            existing = self.spaces.get_record(ref.record_uri(did, collection, rkey))
            if record is None:
                if existing:
                    prepared.append(prepare_write(did, ref, "delete", collection, rkey))
                continue
            write = prepare_write(did, ref, "update" if existing else "create", collection, rkey, record)
            if not existing or existing["cid"] != write["cid"]:
                prepared.append(write)
        return self._commit_out(self.spaces.apply_writes(did, space, prepared, self._known_blob))

    async def space_create(self, space: str, policy: dict) -> dict | None:
        policy = normalize_policy(policy)
        self.spaces.create_space(space, policy)
        return self._publish(space, [policy_record_write(policy)])

    async def space_update(self, space: str, policy: dict) -> dict | None:
        """Replace the policy wholesale; a different `$type` discards the old policy's state."""
        policy = normalize_policy(policy)
        current = self.spaces.get_active_policy(space)
        writes = [policy_record_write(policy)]
        if are_members_published(current) != are_members_published(policy):
            writes += [member_record_write(policy, member["did"], member)
                       for member in self.spaces.list_members(space)]
        self.spaces.set_policy(space, policy)
        if current["$type"] != policy["$type"]:
            self.spaces.remove_all_members(space)
        return self._publish(space, writes)

    async def space_get(self, space: str) -> dict:
        return self.spaces.get_active_policy(space)

    async def space_status(self, space: str) -> dict:
        existing = self.spaces.get_space(space)
        return {"deleted": bool(existing and existing["deleted_at"]), "policy": self.spaces.get_policy(space)}

    async def space_delete(self, space: str) -> list[dict]:
        return self.spaces.delete_space(space)

    async def space_put_member(self, space: str, did: str, read: bool, write: bool) -> dict | None:
        policy = self.spaces.get_active_policy(space)
        assert_memberspace(policy)
        self.spaces.put_member(space, did, read, write)
        if not write:
            self.spaces.remove_writer(space, did)
        return self._publish(space, [member_record_write(policy, did, {"read": read, "write": write})])

    async def space_remove_member(self, space: str, did: str) -> dict | None:
        policy = self.spaces.get_active_policy(space)
        assert_memberspace(policy)
        self.spaces.remove_member(space, did)
        self.spaces.remove_writer(space, did)
        return self._publish(space, [member_record_write(policy, did, None)])

    async def space_list_members(self, space: str, limit: int, cursor: str | None = None) -> list[dict]:
        assert_memberspace(self.spaces.get_active_policy(space))
        return self.spaces.list_members(space, limit, cursor)

    async def space_remove_writer(self, space: str, did: str) -> None:
        self.spaces.get_active_policy(space)
        self.spaces.remove_writer(space, did)

    async def space_export_meta(self, space: str) -> bytes:
        policy = self.spaces.get_active_policy(space)
        members = self.spaces.list_members(space) if policy["$type"] == MEMBERSPACE else []
        return serialize_space_meta(space, policy, members, self.spaces.list_writers(space, None, None))

    async def space_import_meta(self, space: str, policy: dict, members: list, writers: list) -> None:
        """Replace this host's state for a space whose authority's account moved here,
        from a parsed space meta archive. Its published records arrive with the
        authority's repo (importRepo), so nothing is published."""
        self.spaces.import_space(space, policy, members, writers)

    async def space_list_collections(self, space: str) -> list[str]:
        return self.spaces.list_collections(space)

    async def space_clear_records(self, space: str, granted: list | None = None) -> dict | None:
        """Delete every record in this account's repo in `space` (in its own space, all
        but the published policy and member records) at a new rev; returns the commit,
        or None for a no-op. `granted` lists the collections an OAuth caller may delete;
        None is full access."""
        keep = PUBLISHED_COLLECTIONS if parse_space(space).did == self._did() else ()
        if granted is not None:
            for collection in self.spaces.list_collections(space):
                if collection not in keep and collection not in granted:
                    raise XrpcError("InsufficientScope", f"Scope does not permit delete of {collection}", 403)
        return self._commit_out(self.spaces.clear_records(space, keep))

    async def space_import_repo(self, space: str, records: list) -> None:
        """Replace this account's repo in `space` with records read by read_own_repo_star."""
        self.spaces.import_repo(self._did(), space, [tuple(record) for record in records])

    async def space_get_member(self, space: str, did: str) -> dict | None:
        return self.spaces.get_member(space, did)

    async def space_record_writer(self, space: str, did: str, repo_rev: str, hash: bytes) -> dict | None:
        return self.spaces.record_writer(space, did, repo_rev, hash)

    async def space_list_writers(self, space: str, limit: int, cursor: str | None = None) -> list[dict]:
        return self.spaces.list_writers(space, limit, cursor)

    async def space_register_recipient(self, space: str, service: str, endpoint: str) -> str:
        return self.spaces.register_recipient(space, service, endpoint)

    async def space_unregister_recipient(self, space: str, service: str) -> None:
        self.spaces.unregister_recipient(space, service)

    async def space_recipients(self, space: str) -> list[dict]:
        return self.spaces.get_recipients(space)

    # This account's repo in a space

    async def space_apply_writes(self, space: str, writes: list) -> dict:
        did, ref = self._did(), parse_space(space)
        if len(writes) > MAX_WRITES:
            raise XrpcError("InvalidRequest", f"Too many writes. Max: {MAX_WRITES}")
        prepared = []
        for write in writes:
            action = WRITE_TYPES.get(write.get("$type")) if isinstance(write, dict) else None
            if action is None:
                raise XrpcError("InvalidRequest", f"Action not supported: {write}")
            if action != "create" and not write.get("rkey"):
                raise XrpcError("InvalidRequest", f"{action} requires rkey")
            prepared.append(prepare_write(did, ref, action, write.get("collection"), write.get("rkey"),
                                          write.get("value")))
        commit = self.spaces.apply_writes(did, space, prepared, self._known_blob)
        return {"results": [write_result(write) for write in prepared], "commit": self._commit_out(commit)}

    async def space_put_record(self, space: str, collection: str, rkey: str, record, mode: str = "put") -> dict:
        """mode "create" | "put" (create or update) | "delete"; returns the write and commit."""
        did, ref = self._did(), parse_space(space)
        uri = ref.record_uri(did, collection, rkey) if rkey else None
        if mode == "put":
            action = "update" if uri and self.spaces.has_record(uri) else "create"
        elif mode == "delete":
            if uri and not self.spaces.has_record(uri):
                return {"action": "delete", "write": None, "commit": None}
            action = "delete"
        else:
            action = "create"
        write = prepare_write(did, ref, action, collection, rkey, record)
        commit = self.spaces.apply_writes(did, space, [write], self._known_blob)
        return {"action": action, "write": write_result(write), "commit": self._commit_out(commit)}

    async def space_get_record(self, space: str, collection: str, rkey: str,
                               key_share: str | None = None) -> dict | None:
        ref = parse_space(space)
        uri = ref.record_uri(self._did(), collection, rkey)
        secret = self._mac_secret(key_share)
        record = self.spaces.get_record(uri)
        if not record:
            return None
        mac = compute_record_mac(secret, uri, CID.parse(record["cid"]).bytes) if secret else None
        return dict(record, uri=uri, mac=mac)

    async def space_list_records(self, space: str, limit: int, cursor: str | None = None, reverse: bool = False,
                                 collection: str | None = None, exclude_values: bool = False) -> list[dict]:
        return self.spaces.list_records(space, limit, cursor, reverse, collection, exclude_values)

    async def space_list_repo_ops(self, space: str, limit: int, since: str | None = None, cursor: list | None = None,
                                  exclude_values: bool = False, key_share: str | None = None) -> dict:
        """{ops, commit, mac}: a full page has no commit (and so no MAC); the last page does."""
        self._mac_secret(key_share)  # a bad key share fails every page, as in the reference
        ops = self.spaces.list_repo_ops(space, limit, since, tuple(cursor) if cursor else None, exclude_values)
        head = None if len(ops) == limit else self._commit_with_mac(space, key_share)
        return {"ops": ops, "commit": head and head["commit"], "mac": head and head["mac"]}

    async def space_latest_commit(self, space: str, key_share: str | None = None) -> dict | None:
        """{commit, mac}, or None when the repo has never been written to."""
        return self._commit_with_mac(space, key_share)

    async def space_export_star(self, space: str, key_share: str | None = None) -> dict | None:
        """{data (a STAR archive), mac}, or None when the repo has never been written to."""
        head = self._commit_with_mac(space, key_share)
        if head is None:
            return None
        return {"data": self.spaces.export_star(space, head["commit"]), "mac": head["mac"]}

    async def space_list_blobs(self, space: str, limit: int, since: str | None = None,
                               cursor: str | None = None) -> list[str]:
        return self.spaces.list_blobs(space, limit, since, cursor)

    async def space_has_blob(self, space: str, cid: str) -> bool:
        return self.spaces.is_blob_in_space(space, cid)

    async def space_list_spaces(self, limit: int, cursor: str | None = None, space_type: str | None = None,
                                authority: str | None = None) -> list[str]:
        return self.spaces.list_spaces(limit, cursor, space_type, authority)

    # Keys

    async def space_sign_token(self, token_type: str, sub: str, aud: str | None = None,
                               key_id: str | None = None) -> str:
        if token_type not in ("delegation", "credential"):
            raise XrpcError("InvalidRequest", f"cannot mint a {token_type} token")
        return build_token(token_type, self._keypair().sign, iss=self._did(), sub=sub, aud=aud, key_id=key_id)

    async def space_signing_key(self) -> str:
        return self._keypair().did()

    async def space_kem_key(self, create: bool = False) -> str | None:
        """The did:key of this account's #atproto_kem key; `create` makes one if it has none."""
        private_key_hex = self.spaces.kem_key_hex()
        if private_key_hex is None:
            if not create:
                return None
            self.spaces.set_kem_key_hex(P256Keypair().export_hex())
            private_key_hex = self.spaces.kem_key_hex()
        return P256Keypair.import_hex(private_key_hex).did()

    # Write notifications owed to space hosts

    async def space_queue_notification(self, space: str, repo_rev: str, hash: bytes, attempts: int,
                                       retry_at: int, expires_at: int) -> None:
        self.spaces.queue_notification(space, repo_rev, hash, attempts, retry_at, expires_at)

    async def space_clear_notification(self, space: str, repo_rev: str) -> None:
        self.spaces.clear_notification(space, repo_rev)

    async def space_due_notifications(self) -> list[dict]:
        return self.spaces.due_notifications(int(time.time() * 1000))

    # Deletion notices owed to syncers of spaces this account deleted

    async def space_queue_deletion_notice(self, space: str, service_did: str, attempts: int, retry_at: int,
                                          expires_at: int) -> None:
        self.spaces.queue_deletion_notice(space, service_did, attempts, retry_at, expires_at)

    async def space_clear_deletion_notice(self, space: str, service_did: str) -> None:
        self.spaces.clear_deletion_notice(space, service_did)

    async def space_due_deletion_notices(self) -> list[dict]:
        return self.spaces.due_deletion_notices(int(time.time() * 1000))
