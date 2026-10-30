# SPDX-License-Identifier: MIT
# Copyright (c) 2026 sol pbc

"""atproto identifier syntax, as in @atproto/syntax."""

import re

_NSID_RE = re.compile(
    r"^[a-zA-Z](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+"
    r"(?:\.[a-zA-Z](?:[a-zA-Z0-9]{0,62})?)$"
)
_DID_RE = re.compile(r"^did:[a-z]+:[a-zA-Z0-9._:%-]*[a-zA-Z0-9._-]$")
_RKEY_RE = re.compile(r"^[a-zA-Z0-9_~.:-]{1,512}$")
_TID_RE = re.compile(r"^[234567abcdefghij][234567abcdefghijklmnopqrstuvwxyz]{12}$")


class InvalidHandleError(ValueError):
    pass


def is_valid_nsid(value: str) -> bool:
    return isinstance(value, str) and 5 <= len(value) <= 317 and bool(_NSID_RE.match(value))


def is_valid_did(value: str) -> bool:
    return isinstance(value, str) and len(value) <= 2048 and bool(_DID_RE.match(value))


def is_valid_record_key(value: str) -> bool:
    return isinstance(value, str) and value not in (".", "..") and bool(_RKEY_RE.match(value))


def is_valid_tid(value: str) -> bool:
    return isinstance(value, str) and bool(_TID_RE.match(value))


def ensure_valid_handle(value: str) -> None:
    if not re.match(r"^[a-zA-Z0-9.-]*$", value):
        raise InvalidHandleError("Disallowed characters in handle (ASCII letters, digits, dashes, periods only)")
    if len(value) > 253:
        raise InvalidHandleError("Handle is too long (253 chars max)")
    labels = value.split(".")
    if len(labels) < 2:
        raise InvalidHandleError("Handle domain needs at least two parts")
    for index, label in enumerate(labels):
        if not label:
            raise InvalidHandleError("Handle parts can not be empty")
        if len(label) > 63:
            raise InvalidHandleError("Handle part too long (max 63 chars)")
        if label.startswith("-") or label.endswith("-"):
            raise InvalidHandleError("Handle parts can not start or end with hyphens")
        if index + 1 == len(labels) and not re.match(r"^[a-zA-Z]", label):
            raise InvalidHandleError("Handle final component (TLD) must start with ASCII letter")
