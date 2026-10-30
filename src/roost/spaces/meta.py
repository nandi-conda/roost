# SPDX-License-Identifier: MIT
# Copyright (c) 2026 sol pbc

"""The space meta archive, as space-meta-archive.ts in @atproto/space: a space
authority's host-side state, carried between hosts when its account migrates
(exportSpaceMeta, importSpaceMeta).

A STAR archive with the `atproto-space-meta` profile, metadata
{$type, ver: 1, space}, then three sections in this order, each in strict byte
order of its keys:

    policy                                  the policy object
    com.atproto.memberspace.member/<rkey>   {$type, read, write} (memberspace only)
    writer/<did>                            {rev, data, spaceRev}
"""

from .. import cbor
from ..syntax import is_valid_did, is_valid_tid
from .policy import MEMBER_COLLECTION, MEMBERSPACE, did_to_rkey, rkey_to_did
from .star import StarParseError, read_star, write_star

SPACE_META_STAR_TYPE = "atproto-space-meta"
SPACE_META_VERSION = 1
POLICY_KEY = "policy"
MEMBER_PREFIX = f"{MEMBER_COLLECTION}/"
WRITER_PREFIX = "writer/"
SECTIONS = ("policy", "policyState", "writers")


class SpaceMetaArchiveError(ValueError):
    pass


def _sorted(pairs: list[tuple[str, bytes]]) -> list[tuple[str, bytes]]:
    return sorted(pairs, key=lambda pair: pair[0].encode())


def serialize_space_meta(space: str, policy: dict, members: list[dict], writers: list[dict]) -> bytes:
    """`members` [{did, read, write}], `writers` [{did, repoRev, data, spaceRev}]."""
    state = [(f"{MEMBER_PREFIX}{did_to_rkey(m['did'])}",
              cbor.encode({"$type": MEMBER_COLLECTION, "read": m["read"], "write": m["write"]})) for m in members]
    writer_pairs = [(f"{WRITER_PREFIX}{w['did']}",
                     cbor.encode({"rev": w["repoRev"], "data": w["data"], "spaceRev": w["spaceRev"]}))
                    for w in writers]
    meta = {"$type": SPACE_META_STAR_TYPE, "ver": SPACE_META_VERSION, "space": space}
    return write_star(meta, [(POLICY_KEY, cbor.encode(policy)), *_sorted(state), *_sorted(writer_pairs)])


def _section(key: str) -> str:
    if key == POLICY_KEY:
        return "policy"
    return "writers" if key.startswith(WRITER_PREFIX) else "policyState"


def _decode_map(key: str, value: bytes) -> dict:
    try:
        decoded = cbor.decode(value)
    except ValueError as exc:
        raise SpaceMetaArchiveError(f"invalid cbor at {key}") from exc
    if not isinstance(decoded, dict):
        raise SpaceMetaArchiveError(f"value at {key} is not a map")
    return decoded


def read_space_meta(data: bytes) -> dict:
    """{space, policy, state: [(key, value)], writers: [{did, rev, data, spaceRev}]};
    rejects a missing policy, sections or keys out of order, and duplicate keys."""
    try:
        meta, pairs = read_star(data, SPACE_META_STAR_TYPE)
    except StarParseError as exc:
        raise SpaceMetaArchiveError(str(exc)) from exc
    if meta.get("ver") != SPACE_META_VERSION or not isinstance(meta.get("space"), str):
        raise SpaceMetaArchiveError("invalid space meta metadata")
    policy, state, writers = None, [], []
    section, prev = None, None
    for key, value in pairs:
        key_section = _section(key)
        if key_section != section:
            if section and SECTIONS.index(key_section) < SECTIONS.index(section):
                raise SpaceMetaArchiveError(f"section out of order at {key}")
            section, prev = key_section, None
        if prev is not None and key.encode() <= prev:
            raise SpaceMetaArchiveError(f"duplicate or out-of-order key: {key}")
        prev = key.encode()
        decoded = _decode_map(key, value)
        if key_section == "policy":
            policy = decoded
        elif key_section == "policyState":
            state.append((key, decoded))
        else:
            did = key[len(WRITER_PREFIX):]
            rev, digest, space_rev = decoded.get("rev"), decoded.get("data"), decoded.get("spaceRev")
            if not is_valid_did(did) or not is_valid_tid(rev) or not is_valid_tid(space_rev) \
                    or not isinstance(digest, bytes) or len(digest) != 32:
                raise SpaceMetaArchiveError(f"invalid writer at {key}")
            writers.append({"did": did, "rev": rev, "data": digest, "spaceRev": space_rev})
    if policy is None:
        raise SpaceMetaArchiveError("missing policy")
    return {"space": meta["space"], "policy": policy, "state": state, "writers": writers}


def parse_members(policy: dict, state: list[tuple[str, dict]]) -> list[dict]:
    """The member list out of an archive's policy state. A key the (normalized) policy
    doesn't define is refused, never dropped: dropping it would change who has access."""
    members = []
    for key, value in state:
        did = rkey_to_did(key[len(MEMBER_PREFIX):]) if key.startswith(MEMBER_PREFIX) else None
        if policy["$type"] != MEMBERSPACE or not is_valid_did(did):
            raise SpaceMetaArchiveError(f"Unrecognized policy state: {key}")
        read, write = value.get("read"), value.get("write")
        if value.get("$type", MEMBER_COLLECTION) != MEMBER_COLLECTION or not isinstance(read, bool) \
                or not isinstance(write, bool):
            raise SpaceMetaArchiveError(f"Invalid member at {key}")
        members.append({"did": did, "read": read, "write": write})
    return members
