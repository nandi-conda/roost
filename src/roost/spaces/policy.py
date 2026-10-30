# SPDX-License-Identifier: MIT
# Copyright (c) 2026 sol pbc

"""Space policies, as space-policy/ in the reference PDS. A space is governed by one
policy object, an open union on `$type`; every PDS supports the three baselines:

- personalspace: only the authority reads or writes.
- memberspace: a member list (or publicRead/publicWrite), and optionally an
  allow-list of apps judged by the attested client_id.
- managedspace: every user decision, read and write, goes to the managing app's
  com.atproto.managedspace.checkUserAccess.

memberspace and managedspace can publish their configuration to readers as records
in the authority's own repo in the space (publishPolicy, publishMembers)."""

import logging
import re
import time
from urllib.parse import urlencode

from ..errors import XrpcError
from .identity import service_endpoint
from .refs import SpaceRef

log = logging.getLogger("roost.spaces")

PERSONALSPACE = "com.atproto.personalspace.policy"
MEMBERSPACE = "com.atproto.memberspace.policy"
MANAGEDSPACE = "com.atproto.managedspace.policy"
CHECK_USER_ACCESS = "com.atproto.managedspace.checkUserAccess"

POLICY_COLLECTION = "com.atproto.space.policy"
POLICY_RKEY = "self"
MEMBER_COLLECTION = "com.atproto.memberspace.member"
PUBLISHED_COLLECTIONS = (POLICY_COLLECTION, MEMBER_COLLECTION)


def _flag(policy: dict, field: str) -> bool:
    value = policy.get(field, False)
    if not isinstance(value, bool):
        raise XrpcError("InvalidRequest", f"policy.{field} must be a boolean")
    return value


def normalize_policy(policy) -> dict:
    """Check this host implements the policy and fill in its defaults, dropping unknown
    fields, so that what is stored is exactly what is enforced."""
    if not isinstance(policy, dict):
        raise XrpcError("InvalidRequest", "policy must be an object")
    kind = policy.get("$type")
    if kind == PERSONALSPACE:
        return {"$type": PERSONALSPACE}
    if kind == MEMBERSPACE:
        out = {"$type": MEMBERSPACE, "publicRead": _flag(policy, "publicRead"),
               "publicWrite": _flag(policy, "publicWrite")}
        if policy.get("allowedApps") is not None:
            allowed = policy["allowedApps"]
            if not isinstance(allowed, list) or not all(isinstance(item, str) for item in allowed):
                raise XrpcError("InvalidRequest", "policy.allowedApps must be a list of client IDs")
            out["allowedApps"] = allowed
        out["publishPolicy"] = _flag(policy, "publishPolicy")
        out["publishMembers"] = _flag(policy, "publishMembers")
        return out
    if kind == MANAGEDSPACE:
        managing_app = policy.get("managingApp")
        if not isinstance(managing_app, str) or not managing_app.startswith("did:"):
            raise XrpcError("InvalidRequest",
                            f"managingApp must be a DID with an optional service fragment, got: {managing_app}")
        return {"$type": MANAGEDSPACE, "managingApp": managing_app, "publishPolicy": _flag(policy, "publishPolicy")}
    raise XrpcError("UnsupportedPolicy", f"Unsupported policy: {kind}")


def assert_memberspace(policy: dict) -> None:
    if policy["$type"] != MEMBERSPACE:
        raise XrpcError("PolicyMismatch", "Space is not governed by the memberspace policy")


def is_public_read(policy: dict) -> bool:
    return policy["$type"] == MEMBERSPACE and policy["publicRead"]


def is_policy_published(policy: dict) -> bool:
    return policy["$type"] in (MEMBERSPACE, MANAGEDSPACE) and policy["publishPolicy"]


def are_members_published(policy: dict) -> bool:
    return policy["$type"] == MEMBERSPACE and policy["publishMembers"]


def is_app_authorized(policy: dict, client_id: str | None) -> bool:
    """Only memberspace restricts apps, by attested client_id: no attestation, no match."""
    if policy["$type"] != MEMBERSPACE or "allowedApps" not in policy:
        return True
    return client_id is not None and client_id in policy["allowedApps"]


def assert_not_published_collection(collection) -> None:
    """Policy and member records are written only by the PDS, in any repo."""
    if collection in PUBLISHED_COLLECTIONS:
        raise XrpcError("InvalidRequest", f"{collection} records are published by the PDS from a space's "
                                          "configuration and cannot be written directly")


# A DID as a record key (a member's published record). A record key can't hold `%`,
# so a localhost did:web's percent-encoded port is left unencoded; the upstream
# stopgap until Lexicon has a DID record key format.

def did_to_rkey(did: str) -> str:
    return did.replace("%3A", ":", 1)


def rkey_to_did(rkey: str) -> str:
    return re.sub(r"^(did:web:[^:]+):(\d+)$", r"\1%3A\2", rkey)


# Published records: (collection, rkey, record or None to withdraw)

def policy_record_write(policy: dict) -> tuple[str, str, dict | None]:
    record = {"$type": POLICY_COLLECTION, "policy": policy} if is_policy_published(policy) else None
    return POLICY_COLLECTION, POLICY_RKEY, record


def member_record_write(policy: dict, did: str, access: dict | None) -> tuple[str, str, dict | None]:
    """`access` ({read, write}) is None for a DID that is no longer a member."""
    record = None
    if access is not None and are_members_published(policy):
        record = {"$type": MEMBER_COLLECTION, "read": access["read"], "write": access["write"]}
    return MEMBER_COLLECTION, did_to_rkey(did), record


# Authorization

async def authorize_user(env, authority, space: str, policy: dict, user_did: str, access: str,
                         client_id: str | None = None) -> bool:
    """`authority` is the space authority's AccountClient."""
    if user_did == SpaceRef.parse(space).did:
        return True  # the authority can never lock itself out
    kind = policy["$type"]
    if kind == MEMBERSPACE:
        if policy["publicRead" if access == "read" else "publicWrite"]:
            return True
        member = await authority.space_get_member(space=space, did=user_did)
        return bool(member and member[access])
    if kind == MANAGEDSPACE:
        return await _check_managing_app(env, authority, space, policy["managingApp"], user_did, access, client_id)
    return False  # personalspace


async def _check_managing_app(env, authority, space, managing_app, user_did, access, client_id) -> bool:
    try:
        endpoint = await service_endpoint(env, managing_app)
        if not endpoint:
            log.warning("could not resolve managing app %s", managing_app)
            return False
        token = await authority.sign_service_auth(aud=managing_app, lxm=CHECK_USER_ACCESS, exp=int(time.time()) + 60)
        params = {"space": space, "user": user_did, "access": access}
        if client_id:
            params["clientId"] = client_id
        response = await env.http.fetch(
            f"{endpoint}/xrpc/{CHECK_USER_ACCESS}?{urlencode(params)}",
            headers={"Authorization": f"Bearer {token['token']}"}, timeout=10,
        )
        return response.ok and response.json().get("authorized") is True
    except Exception as exc:
        # An unreachable managing app denies: failing open would hand out access to
        # the spaces that asked for the strictest gate.
        log.warning("managing app check failed for %s: %s", space, exc)
        return False


async def authorize_credential(env, authority, space: str, policy: dict, user_did: str | None,
                               client_id: str | None) -> None:
    """The user first, then the app. A refused user, or no delegation token on a space
    without publicRead, is answered as though the space does not exist."""
    if user_did is None:
        user_ok = is_public_read(policy)
    else:
        user_ok = await authorize_user(env, authority, space, policy, user_did, "read", client_id)
    if not user_ok:
        raise XrpcError("SpaceNotFound", "Space not found")
    if not is_app_authorized(policy, client_id):
        raise XrpcError("AppNotAuthorized", "Application not authorized for this space")
