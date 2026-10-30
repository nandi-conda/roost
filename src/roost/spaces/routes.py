# SPDX-License-Identifier: MIT
# Copyright (c) 2026 sol pbc

"""The com.atproto.space.* and com.atproto.memberspace.* XRPC routes.

Rookery plays every PDS role in the spaces design: the repo host for its
accounts' records in any space, the space host (authority) for spaces its
accounts create, and the user's PDS that mints delegation tokens.
"""

from ..app import authenticate, clamp, read_json, resolve_or_404, router
from ..errors import XrpcError
from ..keys import p256_did_key_point
from ..lexjson import json_to_lex, lex_to_json
from ..syntax import is_valid_did, is_valid_nsid, is_valid_record_key
from ..tid import next_tid
from ..web import Response, body_response, json_response
from .auth import (
    ensure_revocations,
    is_space_credential,
    verify_client_attestation,
    verify_delegation,
    verify_service_auth,
    verify_space_credential,
)
from .identity import local_account, service_endpoint
from .mac import (
    COMMIT_MAC_TYPE,
    MAC_HEADER,
    RECORD_MAC_TYPE,
    WANT_MAC_HEADER,
    SpaceMacError,
    format_mac_header,
    parse_want_mac_header,
)
from .meta import SpaceMetaArchiveError, parse_members, read_space_meta
from .notify import notify_space_deleted, notify_write, process_notify_write
from .policy import (
    PUBLISHED_COLLECTIONS,
    assert_not_published_collection,
    authorize_credential,
    normalize_policy,
)
from .refs import InvalidSpaceRef, SpaceRef, space_host_aud
from .scopes import space_scope_denial
from .star import StarParseError, read_own_repo_star

X = "/xrpc/com.atproto.space."
M = "/xrpc/com.atproto.memberspace."
# Both imports carry a whole archive through one Durable Object call.
MAX_IMPORT_BYTES = 16 * 1024 * 1024


def ok() -> Response:
    return Response(200, b"", [])


def invalid(message: str) -> XrpcError:
    return XrpcError("InvalidRequest", message)


def parse_space(value) -> SpaceRef:
    try:
        return SpaceRef.parse(value)
    except InvalidSpaceRef as exc:
        raise XrpcError("InvalidRequest", str(exc)) from exc


def require_did(value, field: str) -> str:
    if not is_valid_did(value):
        raise invalid(f"Invalid {field}: {value}")
    return value


def ref_target(ref: SpaceRef) -> dict:
    return {"type": ref.type, "authority": ref.did, "skey": ref.skey}


def check_space_scope(auth: dict, ref_or_target, **op) -> None:
    """OAuth tokens need a covering space: permission; WelcomeMat and session tokens are full access."""
    if auth["kind"] != "oauth":
        return
    target = ref_target(ref_or_target) if isinstance(ref_or_target, SpaceRef) else ref_or_target
    denied = space_scope_denial(auth["scope"], auth["did"], target, **op)
    if denied:
        raise XrpcError("InsufficientScope", f"Scope does not permit {denied}", 403)


async def json_body(request) -> dict:
    body = await read_json(request)
    if body is None:
        raise XrpcError("InvalidRequest", "Invalid JSON body")
    return body


async def space_host(env, space: SpaceRef):
    """The authority's AccountClient, when this host governs the space."""
    host = await local_account(env, space.did)
    if not host:
        raise XrpcError("SpaceNotFound", "Space not found")
    return env.account(host["do_id"])


def assert_owner(auth: dict, ref: SpaceRef) -> None:
    if ref.did != auth["did"]:
        raise XrpcError("NotSpaceOwner", "Not the space owner")


def assert_credential_space(credential: dict, space: str, audience: str | None = None) -> None:
    if credential["audience"] != (audience or SpaceRef.parse(space).did):
        raise XrpcError("BadSpaceAudience", "space audience does not match the request", 401)
    if credential["space"] != space:
        raise XrpcError("InvalidCredential", "Credential is not scoped to this space")


async def read_access(request, env, space: str, repo: str, mac_type: str | None = None) -> dict:
    """Authorize a read of `repo`'s data in `space`: its own account (OAuth needs
    read_self) or a space credential for the space. Returns the repo's directory row,
    plus the requested MAC's `key_share` for methods that return a commit or record
    (`mac_type`): required with a space credential, optional for the account itself."""
    ref = parse_space(space)
    require_did(repo, "repo")
    credential = is_space_credential(request)
    if credential:
        # At a repo host, a credential's audience is the repo's own account.
        assert_credential_space(await verify_space_credential(request, env), space, repo)
    else:
        auth = await authenticate(request, env, request.method)
        if auth["did"] != repo:
            # The same answer an absent repo gets: who holds a repo in a space the
            # caller cannot read is not the caller's business.
            raise XrpcError("RepoNotFound", f"Could not find repo for DID: {repo}")
        check_space_scope(auth, ref, action="read_self")
    resolved = await resolve_or_404(env, repo)
    key_share = None
    if mac_type and (credential or request.header(WANT_MAC_HEADER) is not None):
        try:
            key_share = parse_want_mac_header(request.header(WANT_MAC_HEADER), mac_type)
        except SpaceMacError as exc:
            raise XrpcError(exc.code, str(exc)) from exc
        if p256_did_key_point(key_share) is None:
            raise XrpcError("BadSpaceMac", "key_share must be a P-256 did:key")
    return dict(resolved, key_share=key_share)


def mac_response(response: Response, mac_type: str, mac: bytes | None) -> Response:
    """Every MAC-bearing method varies on the request header; a MAC rides in its own."""
    response.set_header("Vary", WANT_MAC_HEADER)
    if mac is not None:
        response.set_header(MAC_HEADER, format_mac_header(mac_type, mac))
    return response


def repo_not_found(space: str) -> XrpcError:
    return XrpcError("RepoNotFound", f"Could not find repo for space: {space}")


# Writes (repo host)

async def _write(request, env, mode: str):
    auth = await authenticate(request, env, "POST")
    body = await json_body(request)
    space, repo = body.get("space"), body.get("repo")
    ref = parse_space(space)
    if repo != auth["did"]:
        raise XrpcError("Forbidden", "repo must match authenticated user", 403)
    collection, rkey = body.get("collection"), body.get("rkey")
    if not is_valid_nsid(collection):
        raise invalid("Invalid collection")
    assert_not_published_collection(collection)
    if mode != "create" and not is_valid_record_key(rkey):
        raise invalid("Invalid rkey")
    if mode != "delete" and "record" not in body:
        raise invalid("Missing record")
    account = env.account(auth["do_id"])
    if auth["kind"] == "oauth":
        if mode == "put":
            existing = await account.space_get_record(space=space, collection=collection, rkey=rkey)
            check_space_scope(auth, ref, action="update" if existing else "create", collection=collection)
        else:
            check_space_scope(auth, ref, action=mode, collection=collection)
    result = await account.space_put_record(
        space=space, collection=collection, rkey=rkey or None, record=body.get("record"), mode=mode,
    )
    await notify_write(env, account, auth["did"], space, result["commit"])
    if mode == "delete":
        return json_response({})
    out = {key: value for key, value in result["write"].items() if key != "$type"}
    return json_response(out)


@router.post(X + "createRecord")
async def create_record(request, env):
    return await _write(request, env, "create")


@router.post(X + "putRecord")
async def put_record(request, env):
    return await _write(request, env, "put")


@router.post(X + "deleteRecord")
async def delete_record(request, env):
    return await _write(request, env, "delete")


@router.post(X + "applyWrites")
async def apply_writes(request, env):
    auth = await authenticate(request, env, "POST")
    body = await json_body(request)
    space, writes = body.get("space"), body.get("writes")
    ref = parse_space(space)
    if body.get("repo") != auth["did"]:
        raise XrpcError("Forbidden", "repo must match authenticated user", 403)
    if not isinstance(writes, list) or not all(isinstance(write, dict) for write in writes):
        raise invalid("writes must be a list of objects")
    for write in writes:
        assert_not_published_collection(write.get("collection"))
        action = (write.get("$type") or "").rpartition("#")[2]
        if action in ("create", "update", "delete"):
            check_space_scope(auth, ref, action=action, collection=write.get("collection"))
    account = env.account(auth["do_id"])
    result = await account.space_apply_writes(space=space, writes=writes)
    await notify_write(env, account, auth["did"], space, result["commit"])
    return json_response({"results": result["results"]})


# Reads (repo host)

@router.get(X + "getRecord")
async def get_record(request, env):
    space, repo = request.query("space"), request.query("repo")
    collection, rkey = request.query("collection"), request.query("rkey")
    if not is_valid_nsid(collection) or not is_valid_record_key(rkey):
        raise invalid("Invalid collection or rkey")
    resolved = await read_access(request, env, space, repo, RECORD_MAC_TYPE)
    record = await env.account(resolved["do_id"]).space_get_record(
        space=space, collection=collection, rkey=rkey, key_share=resolved["key_share"],
    )
    if not record:
        raise XrpcError("RecordNotFound", f"Could not locate record: {space}/{repo}/{collection}/{rkey}")
    response = json_response({"uri": record["uri"], "cid": record["cid"], "value": record["value"]})
    return mac_response(response, RECORD_MAC_TYPE, record["mac"])


def flag(request, name: str) -> bool:
    return request.query(name) in ("true", "1")


@router.get(X + "listRecords")
async def list_records(request, env):
    space, repo = request.query("space"), request.query("repo")
    collection = request.query("collection")
    if collection is not None and not is_valid_nsid(collection):
        raise invalid("Invalid collection")
    resolved = await read_access(request, env, space, repo)
    limit = clamp(request.query("limit"), 50, 100)
    exclude = flag(request, "excludeValues")
    records = await env.account(resolved["do_id"]).space_list_records(
        space=space, limit=limit, cursor=request.query("cursor") or None, reverse=flag(request, "reverse"),
        collection=collection, exclude_values=exclude,
    )
    out = {"records": [{k: v for k, v in record.items() if k != "uri"} for record in records]}
    if len(records) == limit:
        out["cursor"] = records[-1]["uri"]
    return json_response(out)


@router.get(X + "getLatestCommit")
async def get_latest_commit(request, env):
    space, repo = request.query("space"), request.query("repo")
    resolved = await read_access(request, env, space, repo, COMMIT_MAC_TYPE)
    head = await env.account(resolved["do_id"]).space_latest_commit(space=space, key_share=resolved["key_share"])
    if not head:
        raise repo_not_found(space)
    return mac_response(json_response({"commit": lex_to_json(head["commit"])}), COMMIT_MAC_TYPE, head["mac"])


@router.get(X + "getRepo")
async def get_repo(request, env):
    space, repo = request.query("space"), request.query("repo")
    resolved = await read_access(request, env, space, repo, COMMIT_MAC_TYPE)
    archive = await env.account(resolved["do_id"]).space_export_star(space=space, key_share=resolved["key_share"])
    if archive is None:
        raise repo_not_found(space)
    return mac_response(body_response(archive["data"], 200, "application/octet-stream"), COMMIT_MAC_TYPE,
                        archive["mac"])


@router.get(X + "listRepoOps")
async def list_repo_ops(request, env):
    space, repo = request.query("space"), request.query("repo")
    resolved = await read_access(request, env, space, repo, COMMIT_MAC_TYPE)
    limit = clamp(request.query("limit"), 100, 1000)
    cursor = None
    if request.query("cursor"):
        rev, _, idx = request.query("cursor").partition("/")
        if not idx.isdigit():
            raise XrpcError("MalformedCursor", "Malformed cursor")
        cursor = [rev, int(idx)]
    result = await env.account(resolved["do_id"]).space_list_repo_ops(
        space=space, limit=limit, since=request.query("since") or None, cursor=cursor,
        exclude_values=flag(request, "excludeValues"), key_share=resolved["key_share"],
    )
    ops = result["ops"]
    out = {"ops": [{k: op.get(k) for k in ("rev", "collection", "rkey", "cid", "prev", "value") if k in op}
                   for op in ops]}
    if result["commit"]:
        out["commit"] = lex_to_json(result["commit"])
    elif ops:
        out["cursor"] = f"{ops[-1]['rev']}/{ops[-1]['idx']}"
    # A page without a commit has nothing to MAC: its ops are checked once the last
    # page's commit is compared with the syncer's running set hash.
    return mac_response(json_response(out), COMMIT_MAC_TYPE, result["mac"])


@router.get(X + "listBlobs")
async def list_blobs(request, env):
    space, repo = request.query("space"), request.query("repo")
    resolved = await read_access(request, env, space, repo)
    limit = clamp(request.query("limit"), 500, 1000)
    cids = await env.account(resolved["do_id"]).space_list_blobs(
        space=space, limit=limit, since=request.query("since") or None, cursor=request.query("cursor") or None,
    )
    out = {"cids": cids}
    if len(cids) == limit:
        out["cursor"] = cids[-1]
    return json_response(out)


@router.get(X + "getBlob")
async def get_blob(request, env):
    space, repo, cid = request.query("space"), request.query("repo"), request.query("cid")
    if not cid:
        raise invalid("Missing cid")
    resolved = await read_access(request, env, space, repo)
    # Do not reveal whether a blob the space does not reference exists.
    if not await env.account(resolved["do_id"]).space_has_blob(space=space, cid=cid):
        raise XrpcError("BlobNotFound", "Blob not found")
    found = await env.blobs.get(f"{repo}/{cid}")
    if found is None:
        raise XrpcError("BlobNotFound", "Blob not found")
    data, content_type = found
    response = body_response(data, 200, content_type or "application/octet-stream")
    response.set_header("X-Content-Type-Options", "nosniff")
    response.set_header("Content-Disposition", f'attachment; filename="{cid}"')
    response.set_header("Content-Security-Policy", "default-src 'none'; sandbox")
    return response


@router.get(X + "listSpaces")
async def list_spaces(request, env):
    auth = await authenticate(request, env, "GET")
    space_type, authority = request.query("spaceType"), request.query("did")
    if space_type is not None and not is_valid_nsid(space_type):
        raise invalid("Invalid spaceType")
    if authority is not None:
        require_did(authority, "did")
    check_space_scope(auth, {"type": space_type or "*", "authority": authority or "*", "skey": "*"},
                      action="read_self")
    limit = clamp(request.query("limit"), 50, 100)
    uris = await env.account(auth["do_id"]).space_list_spaces(
        limit=limit, cursor=request.query("cursor") or None, space_type=space_type, authority=authority,
    )
    out = {"spaces": [{"uri": uri} for uri in uris]}
    if len(uris) == limit:
        out["cursor"] = uris[-1]
    return json_response(out)


# Credentials

@router.get(X + "getDelegationToken")
async def get_delegation_token(request, env):
    auth = await authenticate(request, env, "GET")
    space = request.query("space")
    ref = parse_space(space)
    check_space_scope(auth, ref, action="read")
    account = env.account(auth["do_id"])
    if ref.did == auth["did"]:
        # For the user's own space, say SpaceNotFound now rather than letting the app's
        # credential exchange fail later; clients such as Colibri create the space on it.
        await account.space_get(space=str(ref))
    token = await account.space_sign_token(
        token_type="delegation", sub=str(ref), aud=space_host_aud(ref.did),
    )
    return json_response({"token": token})


@router.post(X + "getSpaceCredential")
async def get_space_credential(request, env):
    """Unauthenticated: the body carries the credential key and, when the space needs
    them, a delegation token (the user) and a client attestation (the app)."""
    body = await json_body(request)
    space, credential_kid = body.get("space"), body.get("credentialKid")
    ref = parse_space(space)
    if p256_did_key_point(credential_kid) is None:
        raise invalid("credentialKid must be a P-256 did:key")
    user_did = None
    if body.get("delegationToken") is not None:
        delegation = await verify_delegation(env, body["delegationToken"])
        if delegation["space"] != space:
            raise XrpcError("InvalidDelegationToken", "Delegation token subject does not match requested space")
        user_did = delegation["user_did"]
    authority = await space_host(env, ref)
    client_id = None
    if body.get("clientAttestation") is not None:
        if not isinstance(body["clientAttestation"], str):
            raise XrpcError("InvalidClientAttestation", "clientAttestation must be a string")
        client_id = await verify_client_attestation(env, body["clientAttestation"], space_host_aud(ref.did))
    status = await authority.space_status(space=space)
    # A syncer that missed notifySpaceDeleted learns it here, token or not.
    if status["deleted"]:
        raise XrpcError("SpaceDeleted", "Space has been deleted")
    if not status["policy"]:
        raise XrpcError("SpaceNotFound", "Space not found")
    await authorize_credential(env, authority, space, status["policy"], user_did, client_id)
    credential = await authority.space_sign_token(token_type="credential", sub=space, key_id=credential_kid)
    return json_response({"credential": credential})


# Space host: the writer set and notifications

@router.get(X + "listRepos")
async def list_repos(request, env):
    credential = await verify_space_credential(request, env)
    space = request.query("space")
    assert_credential_space(credential, space)
    authority = await space_host(env, parse_space(space))
    limit = clamp(request.query("limit"), 500, 1000)
    writers = await authority.space_list_writers(space=space, limit=limit, cursor=request.query("cursor") or None)
    out = {"repos": [lex_to_json(writer) for writer in writers]}
    if writers:
        out["cursor"] = writers[-1]["spaceRev"]
    return json_response(out)


@router.post(X + "notifyWrite")
async def notify_write_route(request, env):
    service = await verify_service_auth(request, env, "com.atproto.space.notifyWrite")
    body = json_to_lex(await json_body(request))
    space, repo, repo_rev, digest = body.get("space"), body.get("repo"), body.get("repoRev"), body.get("data")
    ref = parse_space(space)
    if not isinstance(repo_rev, str) or not isinstance(digest, bytes):
        raise invalid("repoRev and data are required")
    # iss is the signer, so a PDS cannot notify on another account's behalf.
    if service["iss"] != repo:
        raise XrpcError("Forbidden", "notifyWrite iss does not match claimed writer", 403)
    if service["aud"] not in (ref.did, space_host_aud(ref.did)):
        raise XrpcError("Forbidden", "notifyWrite aud does not match the space authority", 403)
    await process_notify_write(env, space, repo, repo_rev, digest)
    return ok()


@router.post(X + "notifyCredentialRevoked")
async def notify_credential_revoked(request, env):
    service = await verify_service_auth(request, env, "com.atproto.space.notifyCredentialRevoked")
    body = await json_body(request)
    space, credentials = body.get("space"), body.get("credentials")
    ref = parse_space(space)
    if service["iss"] != ref.did:
        raise XrpcError("Forbidden", "Revocation issuer is not the space authority", 403)
    if not is_valid_did(service["aud"]) or not await local_account(env, service["aud"]):
        raise XrpcError("Forbidden", "Revocation audience does not match a repo hosted here", 403)
    if not isinstance(credentials, list) or not all(isinstance(item, str) for item in credentials):
        raise invalid("credentials must be a list of credential ids")
    await ensure_revocations(env)
    await env.db.batch([
        ("INSERT OR IGNORE INTO revoked_space_credentials (space, jti, revoked_at) VALUES (?, ?, datetime('now'))",
         [space, jti]) for jti in credentials[:1000]
    ])
    await env.db.run("DELETE FROM revoked_space_credentials WHERE revoked_at < datetime('now', '-2 hours')")
    return ok()


@router.post(X + "registerNotify")
async def register_notify(request, env):
    credential = await verify_space_credential(request, env)
    body = await json_body(request)
    space, service = body.get("space"), body.get("service")
    assert_credential_space(credential, space)
    authority = await space_host(env, parse_space(space))
    if not isinstance(service, str) or not is_valid_did(service.split("#", 1)[0]):
        raise invalid("service must be a DID with an optional fragment")
    endpoint = await service_endpoint(env, service)
    if not endpoint:
        raise XrpcError("ServiceNotResolvable", f"Could not resolve a service endpoint for {service}")
    expires_at = await authority.space_register_recipient(space=space, service=service, endpoint=endpoint)
    return json_response({"expiresAt": expires_at})


@router.post(X + "unregisterNotify")
async def unregister_notify(request, env):
    credential = await verify_space_credential(request, env)
    body = await json_body(request)
    space, service = body.get("space"), body.get("service")
    assert_credential_space(credential, space)
    authority = await space_host(env, parse_space(space))
    if not isinstance(service, str):
        raise invalid("Missing service")
    await authority.space_unregister_recipient(space=space, service=service)
    return ok()


# Governance of spaces this host's accounts own: the policy (com.atproto.space.*)
# and the memberspace member list (com.atproto.memberspace.*)

def require_policy(body: dict) -> dict:
    """The policy as sent; the authority's DO normalizes what it stores."""
    if "policy" not in body:
        raise invalid("Missing policy")
    return body["policy"]


def owner_space(auth: dict, value, **op) -> SpaceRef:
    ref = parse_space(value)
    check_space_scope(auth, ref, **op)
    assert_owner(auth, ref)
    return ref


@router.post(X + "createSpace")
async def create_space(request, env):
    auth = await authenticate(request, env, "POST")
    body = await json_body(request)
    space_type, skey = body.get("spaceType"), body.get("skey") or next_tid()
    if not is_valid_nsid(space_type):
        raise invalid("Invalid spaceType")
    if not is_valid_record_key(skey):
        raise invalid("Invalid skey")
    ref = SpaceRef(auth["did"], space_type, skey)
    check_space_scope(auth, ref, manage="create")
    account = env.account(auth["do_id"])
    commit = await account.space_create(space=str(ref), policy=require_policy(body))
    await notify_write(env, account, auth["did"], str(ref), commit)
    return json_response({"uri": str(ref)})


@router.post(X + "updateSpace")
async def update_space(request, env):
    auth = await authenticate(request, env, "POST")
    body = await json_body(request)
    ref = owner_space(auth, body.get("space"), manage="update")
    account = env.account(auth["do_id"])
    commit = await account.space_update(space=str(ref), policy=require_policy(body))
    await notify_write(env, account, auth["did"], str(ref), commit)
    return ok()


@router.post(X + "deleteSpace")
async def delete_space(request, env):
    auth = await authenticate(request, env, "POST")
    body = await json_body(request)
    ref = owner_space(auth, body.get("space"), manage="delete")
    account = env.account(auth["do_id"])
    recipients = await account.space_delete(space=str(ref))
    if recipients:
        await notify_space_deleted(env, account, str(ref), recipients)
    return ok()


@router.get(X + "getSpace")
async def get_space(request, env):
    """The owner only: a space credential does not reach the policy, which a space can
    publish to readers as a record instead."""
    auth = await authenticate(request, env, "GET")
    ref = owner_space(auth, request.query("space"), action="read_self")
    policy = await env.account(auth["do_id"]).space_get(space=str(ref))
    return json_response({"uri": str(ref), "policy": policy})


@router.post(X + "removeWriter")
async def remove_writer(request, env):
    auth = await authenticate(request, env, "POST")
    body = await json_body(request)
    ref = owner_space(auth, body.get("space"), manage="update")
    did = require_did(body.get("did"), "did")
    await env.account(auth["do_id"]).space_remove_writer(space=str(ref), did=did)
    return ok()


@router.post(X + "clearRecords")
async def clear_records(request, env):
    auth = await authenticate(request, env, "POST")
    body = await json_body(request)
    space = body.get("space")
    ref = parse_space(space)
    if body.get("repo") != auth["did"]:
        raise XrpcError("Forbidden", "repo must match authenticated user", 403)
    account = env.account(auth["do_id"])
    granted = None
    if auth["kind"] == "oauth":
        # The published policy and member records stay in the authority's repo, and
        # keeping them takes no grant.
        keep = PUBLISHED_COLLECTIONS if ref.did == auth["did"] else ()
        granted = [c for c in await account.space_list_collections(space=str(ref)) if c not in keep]
        for collection in granted:
            check_space_scope(auth, ref, action="delete", collection=collection)
    commit = await account.space_clear_records(space=str(ref), granted=granted)
    await notify_write(env, account, auth["did"], str(ref), commit)
    return json_response({})


async def import_body(request) -> bytes:
    data = await request.bytes()
    if len(data) > MAX_IMPORT_BYTES:
        raise XrpcError("InvalidRequest", f"Archive exceeds {MAX_IMPORT_BYTES} bytes")
    return data


@router.post(X + "importRepo")
async def import_repo(request, env):
    """An account's own repo in a space, from its previous host (a migration)."""
    auth = await authenticate(request, env, "POST")
    try:
        commit, records = read_own_repo_star(await import_body(request))
    except StarParseError as exc:
        raise invalid(f"Invalid STAR: {exc}") from exc
    if commit.get("repo") != auth["did"]:
        raise invalid("Repo does not match the authenticated account")
    ref = parse_space(commit.get("space"))
    for collection in sorted({record[0] for record in records}):
        check_space_scope(auth, ref, action="create", collection=collection)
    await env.account(auth["do_id"]).space_import_repo(space=str(ref), records=records)
    return ok()


@router.get(X + "exportSpaceMeta")
async def export_space_meta(request, env):
    auth = await authenticate(request, env, "GET")
    ref = owner_space(auth, request.query("space"), action="read_self")
    archive = await env.account(auth["do_id"]).space_export_meta(space=str(ref))
    return body_response(archive, 200, "application/octet-stream")


@router.post(X + "importSpaceMeta")
async def import_space_meta(request, env):
    """A space's policy, member list and writer set, as its authority's account moves here."""
    auth = await authenticate(request, env, "POST")
    try:
        archive = read_space_meta(await import_body(request))
    except SpaceMetaArchiveError as exc:
        raise invalid(f"Invalid space meta archive: {exc}") from exc
    ref = parse_space(archive["space"])
    check_space_scope(auth, ref, manage="create")
    owner_space(auth, str(ref), manage="update")
    policy = normalize_policy(archive["policy"])
    try:
        members = parse_members(policy, archive["state"])
    except SpaceMetaArchiveError as exc:
        raise invalid(str(exc)) from exc
    await env.account(auth["do_id"]).space_import_meta(space=str(ref), policy=policy, members=members,
                                                       writers=archive["writers"])
    return ok()


@router.get(M + "listMembers")
async def list_members(request, env):
    auth = await authenticate(request, env, "GET")
    ref = owner_space(auth, request.query("space"), action="read_self")
    limit = clamp(request.query("limit"), 50, 100)
    members = await env.account(auth["do_id"]).space_list_members(
        space=str(ref), limit=limit, cursor=request.query("cursor") or None,
    )
    out = {"members": members}
    if len(members) == limit:
        out["cursor"] = members[-1]["did"]
    return json_response(out)


@router.post(M + "putMember")
async def put_member(request, env):
    auth = await authenticate(request, env, "POST")
    body = await json_body(request)
    ref = owner_space(auth, body.get("space"), manage="update")
    did = require_did(body.get("did"), "did")
    if not isinstance(body.get("read"), bool) or not isinstance(body.get("write"), bool):
        raise invalid("read and write must be booleans")
    account = env.account(auth["do_id"])
    commit = await account.space_put_member(space=str(ref), did=did, read=body["read"], write=body["write"])
    await notify_write(env, account, auth["did"], str(ref), commit)
    return ok()


@router.post(M + "removeMember")
async def remove_member(request, env):
    auth = await authenticate(request, env, "POST")
    body = await json_body(request)
    ref = owner_space(auth, body.get("space"), manage="update")
    account = env.account(auth["do_id"])
    commit = await account.space_remove_member(space=str(ref), did=require_did(body.get("did"), "did"))
    await notify_write(env, account, auth["did"], str(ref), commit)
    return ok()
