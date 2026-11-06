# SPDX-License-Identifier: MIT
# Copyright (c) 2026 sol pbc

"""One agent's repository: the logic behind the Account Durable Object.

Everything here runs inside the account's own Durable Object, so repo writes
for one account are serialized and its keys never leave it. Storage calls are
synchronous SQLite, which makes each commit atomic; only the firehose and R2
calls await.
"""

import json
import time
import uuid

from . import car, cbor
from .cbor import CID, CODEC_RAW, CborError
from .encoding import b64url_encode
from .keys import Secp256k1Keypair
from .lexjson import json_to_lex, lex_to_json
from .repo import Repo, RepoError, Write
from .spaces.account import SpaceMethods
from .storage import RepoStorage

_rkey_counter = 0


def _base36(value: int) -> str:
    digits = "0123456789abcdefghijklmnopqrstuvwxyz"
    out = ""
    while True:
        value, rem = divmod(value, 36)
        out = digits[rem] + out
        if value == 0:
            return out


def next_rkey() -> str:
    global _rkey_counter
    rkey = _base36(int(time.time() * 1000)) + _base36(_rkey_counter)
    _rkey_counter += 1
    return rkey


def to_lex_record(record) -> object:
    if not isinstance(record, dict):
        raise RepoError("Record must be an object")
    lex = json_to_lex(record)
    try:
        cbor.encode(lex)
    except CborError as exc:
        raise RepoError(f"Invalid record: {exc}") from exc
    return lex


class AccountNotProvisioned(RepoError):
    def __init__(self):
        super().__init__("Account not provisioned")


class Account(SpaceMethods):
    """`sql` is the DO's SQLite; `sequencer` has async sequence_commit/identity/account;
    `blobs` is the R2 bucket adapter."""

    def __init__(self, sql, sequencer, blobs):
        self.storage = RepoStorage(sql)
        self.sequencer = sequencer
        self.blobs = blobs

    def init_schema(self) -> None:
        """Create or migrate the account's tables; once per storage, before any call."""
        self.storage.init_schema()
        self.spaces.init_schema()

    # Internals

    def _state(self) -> dict:
        state = self.storage.get_state()
        if not state or not state.get("did"):
            raise AccountNotProvisioned()
        return state

    def _repo(self) -> Repo:
        repo = Repo.load(self.storage)
        if repo is None:
            raise RepoError("Repo not initialized - account may not be provisioned")
        return repo

    def _keypair(self) -> Secp256k1Keypair:
        return Secp256k1Keypair.import_hex(self._state()["signing_key_hex"])

    async def _emit_commit(self, repo: Repo, result) -> None:
        blocks = car.write_car(result.cid, result.blocks.items())
        await self.sequencer.sequence_commit(
            did=repo.did,
            commit=str(result.cid),
            rev=result.rev,
            since=result.since,
            prev_data=str(result.prev_data) if result.prev_data else None,
            blocks=blocks,
            ops=[
                {
                    "action": op["action"],
                    "path": op["path"],
                    "cid": str(op["cid"]) if op["cid"] else None,
                    "prev": str(op["prev"]) if op.get("prev") else None,
                }
                for op in result.ops
            ],
        )

    async def _commit(self, writes: list[Write]):
        repo = self._repo()
        result = repo.apply_writes(writes, self._keypair())
        for write in writes:
            if write.action != "delete":
                self.storage.add_collection(write.collection)
        await self._emit_commit(repo, result)
        return repo, result

    # Provisioning and identity

    async def init_account(self, did, handle, signing_key_hex, signing_key_pub,
                           rotation_key_hex, rotation_key_pub, jwk_thumbprint=None, kem_key_hex=None) -> dict:
        self.storage.init_account_state(
            did=did, handle=handle, signing_key_hex=signing_key_hex,
            signing_key_pub=signing_key_pub, rotation_key_hex=rotation_key_hex,
            rotation_key_pub=rotation_key_pub, jwk_thumbprint=jwk_thumbprint,
        )
        if kem_key_hex:
            self.spaces.set_kem_key_hex(kem_key_hex)
        if Repo.load(self.storage) is None:
            Repo.create(self.storage, did, Secp256k1Keypair.import_hex(signing_key_hex))
        await self.sequencer.sequence_identity(did=did, handle=handle)
        await self.sequencer.sequence_account(did=did, active=True, status=None)
        return {"did": did, "handle": handle}

    async def sign_with_rotation_key(self, data: bytes) -> dict:
        state = self.storage.get_state()
        if not state or not state.get("rotation_key_hex"):
            raise AccountNotProvisioned()
        key = Secp256k1Keypair.import_hex(state["rotation_key_hex"])
        return {"key_did": key.did(), "sig": key.sign(data)}

    async def set_handle(self, handle: str) -> None:
        did = self._state()["did"]
        self.storage.set_handle(handle)
        await self.sequencer.sequence_identity(did=did, handle=handle)

    async def sign_service_auth(self, aud: str, lxm: str, exp: int) -> dict:
        repo = self._repo()
        header = {"typ": "JWT", "alg": "ES256K", "kid": "#atproto"}
        payload = {
            "iss": repo.did,
            "aud": aud,
            "exp": exp,
            "iat": int(time.time()),
            "jti": str(uuid.uuid4()),
            "lxm": lxm,
        }
        signing_input = ".".join(
            b64url_encode(json.dumps(part, separators=(",", ":")).encode()) for part in (header, payload)
        )
        signature = self._keypair().sign(signing_input.encode())
        return {"token": f"{signing_input}.{b64url_encode(signature)}"}

    # Reads

    async def get_state(self) -> dict | None:
        state = self.storage.get_state()
        if not state or not state.get("did"):
            return None
        return {
            "did": state["did"],
            "handle": state["handle"],
            "root_cid": state["root_cid"],
            "rev": state["rev"],
            "active": state["active"] == 1,
        }

    async def account_status(self) -> dict:
        """What com.atproto.server.checkAccountStatus and getRecommendedDidCredentials report."""
        state = self._state()
        return {
            "did": state["did"],
            "handle": state["handle"],
            "active": state["active"] == 1,
            "root_cid": state["root_cid"],
            "rev": state["rev"],
            "signing_did": f"did:key:{state['signing_key_pub']}",
            "rotation_did": f"did:key:{state['rotation_key_pub']}",
            "blocks": self.storage.count_blocks(),
            "records": sum(1 for _ in self._repo().walk_records()),
            "blobs": self.storage.count_blobs(),
        }

    async def get_latest_commit(self) -> dict | None:
        state = self.storage.get_state()
        if not state or not state.get("root_cid") or not state.get("rev"):
            return None
        return {"cid": state["root_cid"], "rev": state["rev"]}

    async def get_repo_status(self) -> dict | None:
        state = self.storage.get_state()
        if not state or not state.get("did"):
            return None
        active = state["active"] == 1
        return {
            "did": state["did"],
            "active": active,
            "status": "active" if active else "deactivated",
            "rev": state["rev"],
        }

    async def describe_repo(self) -> dict:
        repo = self._repo()
        return {
            "did": repo.did,
            "collections": self.storage.get_collections(),
            "cid": str(repo.cid),
            "handle": self._state()["handle"],
        }

    async def has_published(self) -> bool:
        return len(self.storage.get_collections()) > 0

    async def get_record(self, collection: str, rkey: str) -> dict | None:
        found = self._repo().get_record(collection, rkey)
        if found is None:
            return None
        cid, value = found
        return {"cid": str(cid), "record": lex_to_json(value)}

    async def list_records(self, collection: str, limit: int, cursor: str | None = None,
                           reverse: bool = False) -> dict:
        repo = self._repo()
        start = f"{collection}/"
        after = None
        if cursor:
            after = cursor if "/" in cursor else f"{collection}/{cursor}"
            start = max(start, after)
        records = []
        for coll, rkey, cid in repo.walk_records(start):
            if coll != collection:
                break
            if after is not None and f"{coll}/{rkey}" <= after:
                continue
            records.append({
                "uri": f"at://{repo.did}/{coll}/{rkey}",
                "cid": str(cid),
                "value": lex_to_json(repo.read_record(cid)),
            })
            if len(records) > limit:
                break
        has_more = len(records) > limit
        page = records[:limit]
        if reverse:
            page.reverse()
        result = {"records": page}
        if has_more:
            last = records[limit - 1]["uri"].rsplit("/", 1)[1]
            result["cursor"] = f"{collection}/{last}"
        return result

    # Writes

    async def create_record(self, collection: str, rkey: str | None, record) -> dict:
        actual = rkey or next_rkey()
        repo, result = await self._commit([Write("create", collection, actual, to_lex_record(record))])
        return {
            "uri": f"at://{repo.did}/{collection}/{actual}",
            "cid": str(result.ops[0]["cid"]),
            "commit": {"cid": str(result.cid), "rev": result.rev},
        }

    async def put_record(self, collection: str, rkey: str, record) -> dict:
        exists = self._repo().data.get(f"{collection}/{rkey}") is not None
        action = "update" if exists else "create"
        repo, result = await self._commit([Write(action, collection, rkey, to_lex_record(record))])
        return {
            "uri": f"at://{repo.did}/{collection}/{rkey}",
            "cid": str(result.ops[0]["cid"]),
            "commit": {"cid": str(result.cid), "rev": result.rev},
        }

    async def delete_record(self, collection: str, rkey: str) -> dict:
        _, result = await self._commit([Write("delete", collection, rkey)])
        return {"commit": {"cid": str(result.cid), "rev": result.rev}}

    async def apply_writes(self, writes: list) -> dict:
        did = self._state()["did"]
        ops: list[Write] = []
        results = []
        for write in writes:
            kind = write.get("$type")
            collection = write.get("collection")
            if not isinstance(collection, str):
                raise RepoError("Each write requires a collection")
            if kind == "com.atproto.repo.applyWrites#create":
                rkey = write.get("rkey") or next_rkey()
                ops.append(Write("create", collection, rkey, to_lex_record(write.get("value"))))
                results.append({
                    "$type": "com.atproto.repo.applyWrites#createResult",
                    "uri": f"at://{did}/{collection}/{rkey}",
                })
            elif kind == "com.atproto.repo.applyWrites#update":
                if not write.get("rkey"):
                    raise RepoError("Update requires rkey")
                ops.append(Write("update", collection, write["rkey"], to_lex_record(write.get("value"))))
                results.append({
                    "$type": "com.atproto.repo.applyWrites#updateResult",
                    "uri": f"at://{did}/{collection}/{write['rkey']}",
                })
            elif kind == "com.atproto.repo.applyWrites#delete":
                if not write.get("rkey"):
                    raise RepoError("Delete requires rkey")
                ops.append(Write("delete", collection, write["rkey"]))
                results.append({"$type": "com.atproto.repo.applyWrites#deleteResult"})
            else:
                raise RepoError(f"Unknown write $type: {kind}")
        _, result = await self._commit(ops)
        for out, op in zip(results, result.ops):
            if op["cid"] is not None:
                out["cid"] = str(op["cid"])
        return {"commit": {"cid": str(result.cid), "rev": result.rev}, "results": results}

    # Blobs (bytes live in R2, written by the Worker; this tracks metadata)

    async def insert_blob(self, cid: str, mime_type: str, size: int) -> None:
        self._state()
        self.storage.insert_blob(cid, mime_type, size)

    async def list_blobs(self, limit: int = 500, cursor: str | None = None) -> dict:
        return self.storage.list_blobs(limit, cursor)

    # Export, import, takedown

    async def export_repo(self) -> bytes:
        state = self.storage.get_state()
        if not state or not state.get("root_cid"):
            raise RepoError("Repo has no root")
        return car.write_car(CID.parse(state["root_cid"]), self.storage.all_blocks())

    async def get_blocks(self, cids: list[str]) -> bytes:
        found = [(cid, self.storage.get_block(cid)) for cid in cids]
        missing = [cid for cid, raw in found if raw is None]
        if missing:
            raise RepoError(f"Could not find cids: {', '.join(missing)}")
        return car.write_car(None, found)

    async def export_account(self) -> dict:
        return self.storage.dump()

    async def import_account(self, dump: dict) -> None:
        self.storage.restore(dump)
        state = dump["state"]
        active = state.get("active") == 1
        await self.sequencer.sequence_identity(did=state["did"], handle=state["handle"])
        await self.sequencer.sequence_account(
            did=state["did"], active=active, status=None if active else "deactivated"
        )

    async def takedown(self, did: str) -> dict:
        repo = Repo.load(self.storage)
        records = []
        if repo is not None:
            records = [(collection, rkey) for collection, rkey, _ in repo.walk_records("")]
        for offset in range(0, len(records), 200):
            chunk = records[offset:offset + 200]
            await self._commit([Write("delete", collection, rkey) for collection, rkey in chunk])
        await self.sequencer.sequence_account(did=did, active=False, status="deleted")

        blobs_deleted = 0
        cursor = None
        while True:
            keys, cursor = await self.blobs.list(f"{did}/", cursor)
            if keys:
                await self.blobs.delete(keys)
                blobs_deleted += len(keys)
            if cursor is None:
                break
        self.storage.delete_all()
        return {
            "recordsDeleted": len(records),
            "blobsDeleted": blobs_deleted,
            "collections": sorted({collection for collection, _ in records}),
        }


def blob_cid(data: bytes) -> str:
    return str(CID.create(CODEC_RAW, data))
