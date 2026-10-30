# SPDX-License-Identifier: MIT
# Copyright (c) 2026 sol pbc

"""STAR-lite v1 archives, as star.ts in @atproto/space: getRepo's encoding, and the
space meta archive's (see meta.py).

    [ magic | len | meta ] [ len | key | len | value ] ...

Each len is a minimal unsigned varint. The metadata's `$type` names the profile.
For `atproto-space-repo` the metadata is the repo's commit plus `$type`, and each
pair is a record path `{collection}/{rkey}` and its DRISL bytes, in strict byte
order of the path.
"""

from itertools import pairwise

from .. import cbor
from ..cbor import CID, _varint
from ..syntax import is_valid_nsid, is_valid_record_key
from .commit import COMMIT_VERSION, apply_op
from .lthash import LtHash

STAR_MAGIC = bytes([0x2A, 0x6C, 0x01, 0x00])
REPO_STAR_TYPE = "atproto-space-repo"
MAX_RECORD_SIZE = 1024 * 1024
MAX_VARINT_BYTES = 6


class StarParseError(ValueError):
    pass


def _frame(raw: bytes) -> bytes:
    return _varint(len(raw)) + raw


def write_star(meta: dict, pairs) -> bytes:
    """`pairs` yields (key, value bytes) in the profile's order."""
    out = bytearray(STAR_MAGIC)
    out += _frame(cbor.encode(meta))
    for key, value in pairs:
        out += _frame(key.encode()) + _frame(value)
    return bytes(out)


def write_repo_star(commit: dict, records) -> bytes:
    """`records` yields (path, record bytes) in strict path order."""
    records = list(records)
    keys = [path.encode() for path, _ in records]
    if any(a >= b for a, b in pairwise(keys)):
        raise ValueError("STAR records must be in strict path order")
    return write_star({"$type": REPO_STAR_TYPE, **commit}, records)


def _read_varint(data: bytes, pos: int) -> tuple[int | None, int]:
    value = 0
    for i in range(MAX_VARINT_BYTES):
        if pos + i >= len(data):
            if i == 0:
                return None, pos
            raise StarParseError("unexpected end of archive")
        byte = data[pos + i]
        value += (byte & 0x7F) << (7 * i)
        if byte < 0x80:
            if byte == 0 and i > 0:
                raise StarParseError("non-canonical varint")
            return value, pos + i + 1
    raise StarParseError("varint too long")


def _read_frame(data: bytes, pos: int, max_length: int) -> tuple[bytes | None, int]:
    length, pos = _read_varint(data, pos)
    if length is None:
        return None, pos
    if length > max_length:
        raise StarParseError(f"length {length} exceeds limit of {max_length}")
    if pos + length > len(data):
        raise StarParseError("unexpected end of archive")
    return data[pos:pos + length], pos + length


def read_star(data: bytes, star_type: str) -> tuple[dict, list[tuple[str, bytes]]]:
    """(metadata, [(key, value bytes)]) of a whole `star_type` archive, keys in archive
    order; raises StarParseError."""
    if data[:4] != STAR_MAGIC:
        raise StarParseError("invalid magic bytes")
    meta_bytes, pos = _read_frame(data, 4, len(data))
    if meta_bytes is None:
        raise StarParseError("missing metadata")
    try:
        meta = cbor.decode(meta_bytes)
    except Exception as exc:
        raise StarParseError("invalid metadata") from exc
    if not isinstance(meta, dict) or meta.get("$type") != star_type or cbor.encode(meta) != meta_bytes:
        raise StarParseError(f"metadata must be a canonical {star_type} map")
    pairs = []
    while True:
        key, pos = _read_frame(data, pos, len(data))
        if key is None:
            return meta, pairs
        value, pos = _read_frame(data, pos, MAX_RECORD_SIZE)
        if value is None:
            raise StarParseError("missing value for key")
        try:
            pairs.append((key.decode(), value))
        except UnicodeDecodeError as exc:
            raise StarParseError("key is not UTF-8") from exc


def read_repo_star(data: bytes) -> tuple[dict, list[tuple[str, bytes]]]:
    """(metadata, [(path, record bytes)]) of a whole repo archive; raises StarParseError."""
    meta, pairs = read_star(data, REPO_STAR_TYPE)
    keys = [key.encode() for key, _ in pairs]
    if any(a >= b for a, b in pairwise(keys)):
        raise StarParseError("duplicate or out-of-order key")
    return meta, pairs


def read_own_repo_star(data: bytes) -> tuple[dict, list[tuple[str, str, str, bytes]]]:
    """(commit, [(collection, rkey, cid, record bytes)]) of a repo archive whose records
    fold to its commit's data, as readRepoStar: for a repo host importing an account's
    own repo, so the commit is not authenticated. Raises StarParseError."""
    meta, pairs = read_repo_star(data)
    if meta.get("ver") != COMMIT_VERSION:
        raise StarParseError(f"unsupported commit version: {meta.get('ver')}")
    records, set_hash = [], LtHash()
    for path, value in pairs:
        collection, _, rkey = path.partition("/")
        if not is_valid_nsid(collection) or not is_valid_record_key(rkey):
            raise StarParseError(f"invalid record path: {path}")
        try:
            canonical = cbor.encode(cbor.decode(value)) == value
        except ValueError:
            canonical = False
        if not canonical:
            raise StarParseError(f"record is not canonical DRISL at {path}")
        cid = str(CID.for_cbor(value))
        apply_op(set_hash, collection, rkey, cid, None)
        records.append((collection, rkey, cid, value))
    if set_hash.digest() != meta.get("data"):
        raise StarParseError("records do not match the commit data")
    return {k: v for k, v in meta.items() if k != "$type"}, records
