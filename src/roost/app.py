# SPDX-License-Identifier: MIT
# Copyright (c) 2026 sol pbc

"""The roost HTTP API: WelcomeMat enrollment, OAuth, XRPC, invites, operator routes.

`handle(request, env)` is the whole app. `env` carries the configuration
(attribute per variable, None when unset) and the platform services:
db (D1), blobs (R2), account(do_id) / new_account_id() (Account DOs),
subscribe_repos(request) (the Sequencer DO), http (outbound fetch) and
wait_until(coroutine).
"""

import asyncio
import base64
import hmac
import json
import logging
import re
import secrets
import time
from datetime import datetime, timezone
from urllib.parse import urlencode, urlsplit

from . import agentbus, cbor, directory, identity
from .access import AccessJwtError, verify_access_jwt
from .account import blob_cid
from .auth import (
    AuthError,
    extract_bearer_token,
    validate_access_token,
    validate_dpop_proof,
)
from .errors import XrpcError
from .encoding import b64url_decode, b64url_encode, sha256_b64url, sha256_hex
from .handle_dns import HandleDnsError, publish_handle_dns
from .humans import store as human_store
from .humans.pages import render_consent_page
from .mcp import store as mcp_store
from .handle_policy import is_reserved_or_blocked
from .jwt import JwtFormatError, parse_jwt, rs256_verify
from .keys import P256Keypair, Secp256k1Keypair
from .landing import render_landing_page
from .oauth import store
from .oauth.client_metadata import (
    ClientAuthError,
    ClientMetadataError,
    fetch_client_metadata,
    match_redirect_uri,
    rook_cli_client_metadata,
    verify_client_auth,
)
from .oauth.dpop import DpopError, UseDpopNonceError, validate_oauth_dpop_proof
from .oauth.metadata import (
    AUTHORIZE_PATH,
    JWKS_PATH,
    PAR_PATH,
    REVOKE_PATH,
    TOKEN_PATH,
    authorization_server_metadata,
    protected_resource_metadata,
)
from .oauth.nonce import derive_dpop_nonce
from .oauth.resource_server import InvalidOauthTokenError, resolve_oauth_access_token
from .oauth.permission_sets import PermissionSetError, build_token_scope, effective_scope
from .oauth.scopes import enforce_rpc_scope, enforce_scope, is_valid_aud, is_valid_scope_string
from .cbor import CID
from .repo import RepoError
from .spaces.identity import IdentityError, doc_service_endpoint, doc_signing_key, resolve_did_doc
from .syntax import InvalidHandleError, ensure_valid_handle, is_valid_did, is_valid_nsid
from .texts import tos_text, welcome_text
from .urls import parse_url
from .web import (
    Response,
    Router,
    body_response,
    error,
    html_response,
    json_response,
    not_found,
    redirect,
    text_response,
)

log = logging.getLogger("roost")

MAX_BLOB_BYTES = 60 * 1024 * 1024
OAUTH_DISPLAY_FIELDS = ("client_name", "client_uri", "logo_uri", "policy_uri", "tos_uri")
CORS_EXPOSE = (
    "Content-Type,DPoP-Nonce,WWW-Authenticate,Idempotency-Replayed,Atproto-Repo-Rev,Atproto-Content-Labelers,"
    "Atproto-Space-Mac"
)
CORS_ALLOW_METHODS = "GET,HEAD,POST,PUT,DELETE,OPTIONS"
# Preflights reflect the requested headers, as the reference PDS does: clients
# like bsky.app add their own (X-Atproto-Session-Id). This list answers
# preflights that name none.
CORS_ALLOW_HEADERS = (
    "Content-Type,Authorization,DPoP,Idempotency-Key,Accept-Language,"
    "Atproto-Proxy,Atproto-Accept-Labelers,Atproto-Space-Audience,Atproto-Space-Want-Mac,Signature,Signature-Input"
)

router = Router()
_requested_crawl = False


class AuthFailure(Exception):
    """A request's credentials were rejected; carries the response to send."""

    def __init__(self, response: Response):
        super().__init__(response.status)
        self.response = response


# Helpers

def now_s() -> int:
    return int(time.time())


def is_commons(env) -> bool:
    return env.ROOKERY_VARIANT == "commons"


def origin(env) -> str:
    return f"https://{env.ROOKERY_HOSTNAME}"


def request_host(request, env) -> str:
    """The host to check DPoP htu and WelcomeMat aud against: a former hostname in
    ROOKERY_LEGACY_HOSTNAMES when the request reached one, else ROOKERY_HOSTNAME.
    This keeps agents enrolled before a host move working on their old origin."""
    legacy = {host.strip().lower() for host in (env.ROOKERY_LEGACY_HOSTNAMES or "").split(",") if host.strip()}
    host = (urlsplit(request.url).hostname or "").lower()
    return host if host in legacy else env.ROOKERY_HOSTNAME


def legacy_handle_alias(env, handle: str) -> str | None:
    """`handle` moved under ROOKERY_HANDLE_DOMAIN when it ends with a former handle
    domain in ROOKERY_LEGACY_HANDLE_DOMAINS, else None. Accounts keep their name
    when the handle domain changes, so an old handle still finds its account."""
    for domain in (env.ROOKERY_LEGACY_HANDLE_DOMAINS or "").split(","):
        domain = domain.strip().lower()
        if domain and handle.endswith(domain) and "." not in handle[: -len(domain)]:
            return handle[: -len(domain)] + env.ROOKERY_HANDLE_DOMAIN
    return None


def public_request_url(request, env) -> str:
    """The public origin + path for DPoP htu checks."""
    return f"https://{request_host(request, env)}{request.path}{request.search}"


def invite_url(env, token: str) -> str:
    return f"https://{env.ROOKERY_HOSTNAME}/roost#{token}"


def js_int(raw: str | None, default: int) -> int:
    """parseInt(raw || default): leading digits, else the default when NaN."""
    match = re.match(r"^\s*([+-]?\d+)", raw or "")
    return int(match.group(1)) if match else default


def clamp(raw: str | None, default: int, maximum: int) -> int:
    value = js_int(raw, default) if raw else default
    if value < 1:
        value = default
    return min(value, maximum)


def is_js_integer(value) -> bool:
    if isinstance(value, bool):
        return False
    if isinstance(value, int):
        return True
    return isinstance(value, float) and value.is_integer()


def random_b64url(size: int = 32) -> str:
    return b64url_encode(secrets.token_bytes(size))


def invalid_json() -> Response:
    return error("InvalidRequest", "Invalid JSON body", 400)


async def read_json(request) -> dict | None:
    """The JSON body when it is an object; None (-> 400) otherwise."""
    try:
        body = await request.json()
    except (ValueError, UnicodeDecodeError):
        return None
    return body if isinstance(body, dict) else None


def with_query(url: str, params: dict) -> str:
    """URL with `params` set (replacing existing keys), as URL.searchParams.set does."""
    parsed = parse_url(url)
    pairs = [(key, value) for key, value in parsed.params() if key not in params]
    pairs += list(params.items())
    parsed.search = "?" + urlencode(pairs) if pairs else ""
    return parsed.href


# Auth

async def resolve_dpop_auth(request, env, method: str, sessions: bool = True) -> dict:
    """{did, do_id, kind: "wm" | "oauth" | "session" | "mcp", scope?} for the request's credentials."""
    authorization = request.header("authorization") or ""
    if sessions and authorization[:7].lower() == "bearer ":
        token = authorization[7:].strip()
        if mcp_store.is_token(token):
            return await _resolve_mcp_token(env, token)
        return await _resolve_password_session(env, token)
    access_token = extract_bearer_token(authorization)
    if not access_token:
        raise AuthError("Missing DPoP authorization")
    dpop = request.header("dpop")
    if not dpop:
        raise AuthError("Missing DPoP proof")
    url = public_request_url(request, env)
    if access_token.startswith("rkat_"):
        resolved = await resolve_oauth_access_token(access_token, dpop, method, url, env, now_s())
        return dict(resolved, kind="oauth")
    proof = validate_dpop_proof(dpop, method, url, access_token)
    validate_access_token(
        access_token, proof["key"], f"https://{request_host(request, env)}", proof["thumbprint"], tos_text(env.ROOKERY_VARIANT),
    )
    await directory.init_directory(env.db)
    resolved = await directory.resolve_by_thumbprint(env.db, proof["thumbprint"])
    return dict(resolved, kind="wm", scope=None)


async def _resolve_password_session(env, token: str) -> dict:
    try:
        session = await human_store.resolve_token(env.db, token, "access")
    except human_store.SessionError as exc:
        # Clients refresh on ExpiredToken (400), as the reference PDS answers.
        expired = "expired" in str(exc)
        raise AuthFailure(error("ExpiredToken" if expired else "InvalidToken", str(exc), 400 if expired else 401)) from exc
    return {"did": session["did"], "do_id": session["do_id"], "kind": "session", "scope": None}


async def _resolve_mcp_token(env, token: str) -> dict:
    try:
        resolved = await mcp_store.resolve_token(env.db, token)
    except mcp_store.TokenError as exc:
        raise AuthFailure(error("InvalidToken", str(exc), 401)) from exc
    return dict(resolved, kind="mcp", scope=None)


def auth_failure(exc: Exception, oauth_token_error: bool = True) -> Response:
    if oauth_token_error and isinstance(exc, InvalidOauthTokenError):
        return error("InvalidToken", str(exc), 401)
    if isinstance(exc, directory.RepoNotFoundError):
        return error("AccountNotFound", "No account for this key", 401)
    message = str(exc)
    if "tos_hash does not match" in message:
        return error("tos_changed", "Terms of service have changed. Re-consent required.", 401)
    return error("AuthRequired" if message.startswith("Missing") else "AuthFailed", message, 401)


async def authenticate(request, env, method: str, oauth_token_error: bool = True, sessions: bool = True) -> dict:
    """`sessions=False` refuses password-session Bearer tokens (agent-only paths)."""
    try:
        return await resolve_dpop_auth(request, env, method, sessions)
    except (AuthError, InvalidOauthTokenError, directory.RepoNotFoundError) as exc:
        raise AuthFailure(auth_failure(exc, oauth_token_error)) from exc


WRITE_ACTIONS = {
    "com.atproto.repo.applyWrites#create": "create",
    "com.atproto.repo.applyWrites#update": "update",
    "com.atproto.repo.applyWrites#delete": "delete",
}


def require_scope(auth: dict, op: str, writes: list[tuple[str, str]], mime_type: str = "") -> None:
    if auth["kind"] == "oauth":
        denied = enforce_scope(auth["scope"], op, writes, mime_type)
        if denied:
            raise AuthFailure(error("InsufficientScope", f"Scope does not permit {denied}", 403))


async def resolve_or_404(env, repo: str, code: str = "RepoNotFound", message: str = "Repository not found") -> dict:
    await directory.init_directory(env.db)
    try:
        return await directory.resolve_repo(env.db, repo)
    except directory.RepoNotFoundError as exc:
        alias = legacy_handle_alias(env, repo.lower())
        if alias:
            return await resolve_or_404(env, alias, code, message)
        raise AuthFailure(error(code, message, 404)) from exc


# Background work

async def _post_json(env, url: str, payload: dict, headers: dict) -> None:
    response = await env.http.fetch(
        url, method="POST", headers=dict(headers, **{"Content-Type": "application/json"}),
        body=json.dumps(payload, separators=(",", ":")),
    )
    if not response.ok:
        raise RuntimeError(f"{response.status} {response.text()[:200]}")


def sync_knot_member(env, subject: str) -> None:
    endpoint = (env.ROOKERY_KNOT_ADMIN_ADD_MEMBER_URL or "").strip()
    secret = env.ROOKERY_KNOT_ADMIN_SECRET
    if not endpoint or not secret:
        return

    async def run():
        try:
            token = base64.b64encode(f"admin:{secret}".encode()).decode()
            await _post_json(env, endpoint, {"subject": subject}, {"authorization": f"Basic {token}"})
        except Exception as exc:
            log.error("knot member sync failed: %s %s", subject, exc)
    env.wait_until(run())


def alert_takedown(env, alert: dict) -> None:
    endpoint = (env.HUB_WEBHOOK_URL or "").strip()
    if not endpoint:
        return

    async def run():
        try:
            await _post_json(env, endpoint, {
                "office": "cso",
                "ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
                "type": "account_takedown",
                "tier": "T4",
                "actor": alert["actor"],
                "did": alert["did"],
                "handle": alert["handle"],
                "records_deleted": alert["recordsDeleted"],
                "blobs_deleted": alert["blobsDeleted"],
                "collections": alert["collections"],
            }, {"X-Hub-Secret": env.HUB_WEBHOOK_SECRET or ""})
        except Exception as exc:
            log.error("takedown security alert delivery failed: %s %s", alert["did"], exc)
    env.wait_until(run())


def request_crawl(env) -> None:
    """Ask the configured relays to crawl this PDS, once per isolate."""
    global _requested_crawl
    hosts = [host.strip() for host in (env.ROOKERY_RELAY_HOSTS or "").split(",") if host.strip()]
    if not hosts or _requested_crawl:
        return
    _requested_crawl = True

    async def run():
        await asyncio.gather(*(
            _post_json(env, f"https://{host}/xrpc/com.atproto.sync.requestCrawl", {"hostname": env.ROOKERY_HOSTNAME}, {})
            for host in hosts
        ), return_exceptions=True)
    env.wait_until(run())


# The app

async def handle(request, env) -> Response:
    if request.method == "OPTIONS":
        response = Response(204, b"", [
            ("Access-Control-Max-Age", "86400"),
            ("Access-Control-Allow-Methods", CORS_ALLOW_METHODS),
            ("Access-Control-Allow-Headers", request.header("access-control-request-headers") or CORS_ALLOW_HEADERS),
            ("Vary", "Access-Control-Request-Headers"),
        ])
    else:
        request_crawl(env)
        response = await _dispatch(request, env)
        if response.raw is not None:
            return response
    response.set_header("Access-Control-Allow-Origin", "*")
    response.set_header("Access-Control-Expose-Headers", CORS_EXPOSE)
    if request.method == "HEAD":
        response.body = b""
    return response


async def _dispatch(request, env) -> Response:
    try:
        if request.path.startswith("/admin/"):
            denied = await admin_gate(request, env)
            if denied:
                return denied
        handler, params = router.match(request.method, request.path)
        if handler is None:
            return not_found()
        request.params = params
        return await handler(request, env)
    except AuthFailure as failure:
        return failure.response
    except directory.DirectoryInitError as exc:
        log.error("directory unavailable: %s", exc)
        return error("DirectoryUnavailable", "Directory is initializing. Please retry.", 503)
    except HandleDnsError as exc:
        log.error("%s", exc)
        return error("HandleDnsFailed", str(exc), 502)
    except XrpcError as exc:
        return error(exc.name, exc.message, exc.status)
    except RepoError as exc:
        return error("InvalidRequest", str(exc), 400)
    except Exception:
        log.exception("unhandled error")
        return error("InternalError", "Internal server error.", 500)


async def admin_gate(request, env) -> Response | None:
    if not is_commons(env) or not env.CF_ACCESS_TEAM_DOMAIN or not env.CF_ACCESS_AUD:
        return not_found()
    assertion = request.header("Cf-Access-Jwt-Assertion")
    if not assertion:
        log.error("admin access denied: no Cf-Access-Jwt-Assertion header")
        return error("AccessDenied", "Access denied.", 403)
    try:
        request.access_claims = await verify_access_jwt(assertion, env)
    except AccessJwtError as exc:
        log.error("admin access denied: %s", exc)
        return error("AccessDenied", "Access denied.", 403)
    return None


# Discovery

@router.get("/")
async def home(request, env):
    if "text/html" not in (request.header("accept") or ""):
        return json_response({"status": "ok"})
    await directory.init_directory(env.db)
    count = await env.db.first("SELECT COUNT(*) AS count FROM accounts WHERE active = 1")
    recent = await env.db.all(
        "SELECT did, handle FROM accounts WHERE active = 1 ORDER BY created_at DESC LIMIT 12"
    )
    return html_response(render_landing_page(
        env.ROOKERY_HOSTNAME, env.ROOKERY_HANDLE_DOMAIN, count["count"] if count else 0, recent, is_commons(env),
    ))


@router.get("/.well-known/welcome.md")
async def welcome(request, env):
    return text_response(welcome_text(env.ROOKERY_VARIANT), content_type="text/markdown; charset=utf-8")


@router.get("/.well-known/oauth-authorization-server")
async def oauth_server_metadata(request, env):
    return json_response(authorization_server_metadata(origin(env)))


@router.get(JWKS_PATH)
async def oauth_jwks(request, env):
    # Roost signs no OAuth artifacts (tokens are opaque, DPoP keys are the client's).
    return json_response({"keys": []})


@router.get("/xrpc/_health")
async def health(request, env):
    return json_response({"status": "ok"})


@router.get("/.well-known/oauth-protected-resource")
async def oauth_resource_metadata(request, env):
    return json_response(protected_resource_metadata(origin(env)))


@router.get("/client-metadata.json")
async def client_metadata(request, env):
    return json_response(rook_cli_client_metadata(env.ROOKERY_HOSTNAME))


@router.get("/tos")
async def tos(request, env):
    content_type = "text/markdown; charset=utf-8" if is_commons(env) else "text/plain; charset=utf-8"
    return text_response(tos_text(env.ROOKERY_VARIANT), content_type=content_type)


@router.get("/roost")
async def roost(request, env):
    if not is_commons(env):
        return not_found()
    page = """<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><meta http-equiv="refresh" content="0; url=/invite"><title>Roost</title></head>
<body><a href="/invite">Continue to roost</a></body>
</html>"""
    return Response(302, page.encode(), [("location", "/invite"), ("content-type", "text/html; charset=utf-8")])


# OAuth

def _display_fields(source: dict) -> dict:
    return {name: source[name] for name in OAUTH_DISPLAY_FIELDS if isinstance(source.get(name), str)}


@router.post(PAR_PATH)
async def oauth_par(request, env):
    now = now_s()
    await store.init_oauth(env.db)
    secret = env.OAUTH_NONCE_SECRET or ""
    nonce = derive_dpop_nonce(secret, now)

    def reply(body: dict, status: int, with_nonce: str = nonce) -> Response:
        return json_response(body, status, {"DPoP-Nonce": with_nonce})

    dpop = request.header("dpop")
    if not dpop:
        return reply({"error": "invalid_request", "error_description": "DPoP proof required"}, 400)
    try:
        proof = await validate_oauth_dpop_proof(
            dpop, "POST", public_request_url(request, env), None, db=env.db, nonce_secret=secret, now=now,
        )
    except UseDpopNonceError as exc:
        return reply({"error": "use_dpop_nonce", "error_description": str(exc)}, 400, exc.nonce)
    except DpopError as exc:
        return reply({"error": "invalid_dpop_proof", "error_description": str(exc)}, 400)
    try:
        form = await request.oauth_params()
    except (ValueError, UnicodeDecodeError):
        return reply({"error": "invalid_request", "error_description": "Invalid request body"}, 400)

    client_id = form.get("client_id")
    if not client_id:
        return reply({"error": "invalid_request", "error_description": "client_id required"}, 400)
    try:
        metadata = await fetch_client_metadata(client_id, env)
    except ClientMetadataError as exc:
        return reply({"error": "invalid_client", "error_description": f"client metadata invalid: {exc}"}, 401)
    try:
        client = await verify_client_auth(
            metadata, form.get("client_assertion_type"), form.get("client_assertion"), origin(env), env.db, now,
        )
    except ClientAuthError:
        return reply({"error": "invalid_client", "error_description": "client authentication failed"}, 401)

    redirect_uri = form.get("redirect_uri")
    scope = form.get("scope")
    problem = (
        "response_type must be code" if form.get("response_type") != "code"
        else "PKCE with S256 is required" if form.get("code_challenge_method") != "S256" or not form.get("code_challenge")
        else "redirect_uri is not registered in the client metadata"
        if not redirect_uri or not any(match_redirect_uri(uri, redirect_uri) for uri in metadata["redirect_uris"])
        else "response_mode must be query or fragment" if form.get("response_mode", "query") not in RESPONSE_MODES
        else None
    )
    if problem:
        return reply({"error": "invalid_request", "error_description": problem}, 400)
    if not scope or not is_valid_scope_string(scope):
        return reply({"error": "invalid_scope", "error_description": "scope is missing atproto or has a malformed token"}, 400)
    try:
        # Resolve permission sets now, so an unresolvable include: fails the request up front.
        await effective_scope(env, scope, now)
    except PermissionSetError as exc:
        return reply({"error": "invalid_scope", "error_description": str(exc)}, 400)

    request_uri = f"urn:ietf:params:oauth:request_uri:{random_b64url()}"
    params = {"response_type": "code"}
    for name in ("state", "login_hint", "response_mode"):
        if name in form:
            params[name] = form[name]
    params.update(_display_fields(metadata))
    await store.insert_par_request(env.db, {
        "request_uri": request_uri,
        "client_id": client["client_id"],
        "params": json.dumps(params, separators=(",", ":"), ensure_ascii=False),
        "code_challenge": form["code_challenge"],
        "redirect_uri": redirect_uri,
        "scope": scope,
        "dpop_jkt": proof["thumbprint"],
        "exp": now + 300,
    }, now)
    return reply({"request_uri": request_uri, "expires_in": 300}, 201)


@router.get(AUTHORIZE_PATH)
async def oauth_authorize(request, env):
    now = now_s()
    await store.init_oauth(env.db)
    request_uri = request.query("request_uri")
    par = await store.get_par_request(env.db, request_uri) if request_uri else None
    if not par or par["exp"] <= now or par["client_id"] != request.query("client_id"):
        return error("invalid_request", "Invalid or expired request_uri", 400)

    params = json.loads(par["params"])
    if request.header("authorization") is None and "text/html" in (request.header("accept") or ""):
        # A browser: humans sign in with their password here (see humans.routes).
        return html_response(render_consent_page(env, par, params))
    if request.header("authorization") is None:
        login_hint = params.get("login_hint")
        return json_response({
            "consent_request": {
                "client_id": par["client_id"],
                "client_metadata": _display_fields(params),
                "scope": par["scope"],
                "redirect_uri": par["redirect_uri"],
                "login_hint": login_hint if isinstance(login_hint, str) else None,
            },
            "how_to_consent": (
                "GET this URL again with an `Authorization: DPoP <wm+jwt>` header and a matching DPoP proof built "
                "from the granting account's welcome-mat credential to grant; the DPoP htu is origin + path only, "
                "without query or fragment; append deny=1 to refuse."
            ),
        })

    # Welcome-mat DPoP proofs bind to /oauth/authorize without the query, so not to
    # a specific request_uri. The jti cache, single-use request_uri, iat window, ath,
    # and TLS cover the practical capture/replay cases.
    deny = request.query("deny") == "1"
    auth = await authenticate(request, env, "GET", oauth_token_error=False, sessions=False)
    if auth["kind"] != "wm":
        return error("AuthFailed", "OAuth access tokens cannot grant consent", 401)
    _, payload, _, _ = parse_jwt(request.header("dpop") or "")
    jti = payload.get("jti")
    if not isinstance(jti, str) or not jti:
        return error("AuthFailed", "DPoP proof missing jti", 401)
    if not await store.insert_dpop_jti(env.db, sha256_b64url(f"oauth-consent:{jti}"), now + 600, now):
        return error("AuthFailed", "DPoP proof replayed", 401)

    return await finish_consent(env, par, auth["did"], deny)


RESPONSE_MODES = ("query", "fragment")


def client_redirect(par: dict, params: dict) -> Response:
    """The authorization response, in the query or the fragment as the client asked."""
    if json.loads(par["params"]).get("response_mode") == "fragment":
        return redirect(f"{par['redirect_uri'].partition('#')[0]}#{urlencode(params)}")
    return redirect(with_query(par["redirect_uri"], params))


async def finish_consent(env, par: dict, did: str, deny: bool) -> Response:
    """Redirect back to the client with a code for `did`, or access_denied."""
    now = now_s()
    issuer = origin(env)
    state = json.loads(par["params"]).get("state")
    extra = {"state": state} if isinstance(state, str) else {}
    if deny:
        await store.consume_par_request(env.db, par["request_uri"])
        return client_redirect(par, {"error": "access_denied", **extra, "iss": issuer})
    if not await store.consume_par_request(env.db, par["request_uri"]):
        return error("invalid_request", "request_uri already used", 400)
    code = random_b64url()
    await store.insert_code(env.db, {
        "code_hash": sha256_b64url(code),
        "client_id": par["client_id"],
        "redirect_uri": par["redirect_uri"],
        "code_challenge": par["code_challenge"],
        "scope": par["scope"],
        "did": did,
        "dpop_jkt": par["dpop_jkt"],
        "exp": now + 60,
    }, now)
    return client_redirect(par, {"code": code, **extra, "iss": issuer})


@router.post(TOKEN_PATH)
async def oauth_token(request, env):
    now = now_s()
    await store.init_oauth(env.db)
    secret = env.OAUTH_NONCE_SECRET or ""
    nonce = derive_dpop_nonce(secret, now)
    issuer = origin(env)

    def oauth_error(code: str, status: int, description: str | None = None) -> Response:
        body = {"error": code}
        if description is not None:
            body["error_description"] = description
        return json_response(body, status, {"DPoP-Nonce": nonce})

    def invalid_grant() -> Response:
        return oauth_error("invalid_grant", 400)

    def tokens(access: str, refresh: str, access_exp: int, scope: str, did: str) -> Response:
        return json_response({
            "access_token": access,
            "token_type": "DPoP",
            "expires_in": access_exp - now,
            "refresh_token": refresh,
            "scope": scope,
            "sub": did,
        }, 200, {"DPoP-Nonce": nonce})

    dpop = request.header("dpop")
    if not dpop:
        return oauth_error("invalid_request", 400, "DPoP proof required")
    try:
        proof = await validate_oauth_dpop_proof(
            dpop, "POST", public_request_url(request, env), None, db=env.db, nonce_secret=secret, now=now,
        )
    except UseDpopNonceError as exc:
        return json_response({"error": "use_dpop_nonce", "error_description": str(exc)}, 400, {"DPoP-Nonce": exc.nonce})
    except DpopError as exc:
        return oauth_error("invalid_dpop_proof", 400, str(exc))
    try:
        form = await request.oauth_params()
    except (ValueError, UnicodeDecodeError):
        return oauth_error("invalid_request", 400, "Invalid request body")

    grant_type = form.get("grant_type")
    if not grant_type:
        return oauth_error("invalid_request", 400)
    if grant_type not in ("authorization_code", "refresh_token"):
        return oauth_error("unsupported_grant_type", 400)
    client_id = form.get("client_id")
    if not client_id:
        return oauth_error("invalid_request", 400, "client_id required")
    try:
        metadata = await fetch_client_metadata(client_id, env)
    except ClientMetadataError as exc:
        return oauth_error("invalid_client", 401, f"client metadata invalid: {exc}")
    try:
        client = await verify_client_auth(
            metadata, form.get("client_assertion_type"), form.get("client_assertion"), issuer, env.db, now,
        )
    except ClientAuthError:
        return oauth_error("invalid_client", 401, "client authentication failed")
    client_id = client["client_id"]

    if grant_type == "authorization_code":
        code = form.get("code")
        if not code:
            return invalid_grant()
        row = await store.consume_code(env.db, sha256_b64url(code))
        if not row:
            return invalid_grant()
        verifier = form.get("code_verifier")
        if (
            row["exp"] <= now or row["client_id"] != client_id or row["redirect_uri"] != form.get("redirect_uri")
            or row["dpop_jkt"] != proof["thumbprint"] or not verifier
            or sha256_b64url(verifier) != row["code_challenge"]
        ):
            return invalid_grant()
        try:
            scope = await build_token_scope(env, row["scope"], now)
        except PermissionSetError as exc:
            return oauth_error("invalid_request", 400, str(exc))
        session_id = random_b64url()
        refresh = f"rkrt_{random_b64url()}"
        access = f"rkat_{random_b64url()}"
        session_exp = now + 1_209_600
        access_exp = now + min(900, session_exp - now)
        await store.insert_session(env.db, {
            "session_id": session_id, "refresh_token_hash": sha256_b64url(refresh), "client_id": row["client_id"],
            "did": row["did"], "scope": scope, "dpop_jkt": row["dpop_jkt"], "exp": session_exp,
        }, now)
        await store.insert_token(env.db, {
            "access_token_hash": sha256_b64url(access), "session_id": session_id, "client_id": row["client_id"],
            "did": row["did"], "scope": scope, "dpop_jkt": row["dpop_jkt"], "exp": access_exp,
        }, now)
        return tokens(access, refresh, access_exp, scope, row["did"])

    refresh = form.get("refresh_token")
    if not refresh:
        return invalid_grant()
    presented_hash = sha256_b64url(refresh)
    session = await store.get_session_by_refresh_hash(env.db, presented_hash)
    if not session:
        return invalid_grant()
    try:
        await directory.resolve_repo(env.db, session["did"])
    except directory.RepoNotFoundError:
        return invalid_grant()
    if session["exp"] <= now or session["client_id"] != client_id or session["dpop_jkt"] != proof["thumbprint"]:
        return invalid_grant()
    new_refresh = f"rkrt_{random_b64url()}"
    if not await store.rotate_session_refresh(env.db, session["session_id"], presented_hash, sha256_b64url(new_refresh)):
        # A refresh token presented twice: revoke the whole session.
        await store.delete_tokens_by_session(env.db, session["session_id"])
        await store.delete_session_by_id(env.db, session["session_id"])
        return invalid_grant()
    access = f"rkat_{random_b64url()}"
    access_exp = now + min(900, session["exp"] - now)
    await store.insert_token(env.db, {
        "access_token_hash": sha256_b64url(access), "session_id": session["session_id"],
        "client_id": session["client_id"], "did": session["did"], "scope": session["scope"],
        "dpop_jkt": session["dpop_jkt"], "exp": access_exp,
    }, now)
    return tokens(access, new_refresh, access_exp, session["scope"], session["did"])


@router.post(REVOKE_PATH)
async def oauth_revoke(request, env):
    await store.init_oauth(env.db)
    try:
        token = (await request.oauth_params()).get("token")
    except (ValueError, UnicodeDecodeError):
        return body_response()
    if not token:
        return body_response()
    token_hash = sha256_b64url(token)
    access = await store.get_token_by_hash(env.db, token_hash)
    session = access or await store.get_session_by_refresh_hash(env.db, token_hash)
    if session:
        await store.delete_tokens_by_session(env.db, session["session_id"])
        await store.delete_session_by_id(env.db, session["session_id"])
    return body_response()


# Invites (commons)

def _extract_invite_token(ref) -> str | None:
    if not isinstance(ref, str) or not ref:
        return None
    try:
        token = parse_url(ref).hash.removeprefix("#").strip()
    except ValueError:
        return None
    return token or None


@router.post("/api/invites")
async def mint_invite(request, env):
    if not is_commons(env):
        return not_found()
    auth = await authenticate(request, env, "POST", oauth_token_error=False)
    if auth["kind"] != "wm":
        return error("AuthFailed", "OAuth access tokens cannot mint invites", 401)
    if not await env.account(auth["do_id"]).has_published():
        return error("MintLocked", "Publish at least one record before minting invites.", 403)
    quota = await directory.get_effective_quota(env.db, auth["did"])
    minted = await directory.mint_rook_invite(env.db, auth["did"], quota)
    if not minted:
        return error("QuotaExceeded", "Invite quota exceeded.", 403)
    return json_response({"token": minted["token"], "url": invite_url(env, minted["token"]), "remaining": minted["remaining"]})


@router.post("/admin/invites")
async def admin_mint_invite(request, env):
    raw_key = request.header("Idempotency-Key")
    key = None
    if raw_key is not None:
        key = raw_key.strip()
        if not key or len(key) > 255:
            return error("InvalidRequest", "Idempotency-Key must be 1-255 characters.", 400)
    await directory.init_directory(env.db)
    minted = await directory.mint_org_invite(env.db, key)
    response = json_response({"token": minted["token"], "url": invite_url(env, minted["token"])})
    if minted["replayed"]:
        response.set_header("Idempotency-Replayed", "true")
    return response


def _decode_invite_cursor(cursor: str) -> dict | None:
    try:
        decoded = b64url_decode(cursor).decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        return None
    separator = decoded.rfind(" ")
    if separator <= 0 or separator == len(decoded) - 1:
        return None
    return {"minted_at": decoded[:separator], "token": decoded[separator + 1:]}


@router.get("/admin/invites")
async def admin_list_invites(request, env):
    await directory.init_directory(env.db)
    raw_limit = request.query("limit")
    try:
        parsed = float(raw_limit) if raw_limit is not None and raw_limit.strip() else (0.0 if raw_limit is not None else 100.0)
    except ValueError:
        parsed = 0.5
    limit = min(500, max(1, int(parsed))) if parsed.is_integer() else 100
    state = request.query("state")
    if state is not None and state not in ("unspent", "spent"):
        return error("InvalidRequest", "state must be 'unspent' or 'spent'", 400)
    cursor = None
    raw_cursor = request.query("cursor")
    if raw_cursor:
        cursor = _decode_invite_cursor(raw_cursor)
        if cursor is None:
            return error("InvalidRequest", "Invalid cursor", 400)
    records = await directory.list_invites(env.db, limit, cursor, state)
    body = {"records": records}
    if len(records) == limit:
        last = records[-1]
        body["cursor"] = b64url_encode(f"{last['minted_at']} {last['token']}".encode())
    return json_response(body)


@router.delete("/admin/invites/:token")
async def admin_revoke_invite(request, env):
    await directory.init_directory(env.db)
    token = request.params["token"]
    outcome = await directory.revoke_invite(env.db, token)
    if outcome == "not_found":
        return error("InviteNotFound", "Invite not found.", 404)
    if outcome == "spent":
        return error("InviteSpent", "Cannot revoke a spent invite.", 409)
    return json_response({"token": token, "revoked": True})


@router.put("/admin/quotas/:did")
async def admin_set_quota(request, env):
    did = request.params["did"]
    body = await read_json(request)
    if body is None:
        return invalid_json()
    quota = body.get("quota")
    if not did or not is_js_integer(quota) or quota < 0:
        return error("InvalidRequest", "quota must be a non-negative integer", 400)
    await directory.init_directory(env.db)
    await directory.set_invite_quota(env.db, did, int(quota))
    return json_response({"did": did, "quota": quota})


@router.put("/admin/config/invite_quota_default")
async def admin_set_quota_default(request, env):
    body = await read_json(request)
    if body is None:
        return invalid_json()
    value = body.get("value")
    if not is_js_integer(value) or value < 0:
        return error("InvalidRequest", "value must be a non-negative integer", 400)
    await directory.init_directory(env.db)
    await directory.set_invite_quota_default(env.db, int(value))
    return json_response({"value": value})


@router.delete("/admin/accounts/:did")
async def admin_takedown(request, env):
    body = await read_json(request)
    if body is None:
        return invalid_json()
    await directory.init_directory(env.db)
    await store.init_oauth(env.db)
    account = await directory.resolve_account_for_takedown(env.db, request.params["did"])
    if not account:
        return error("AccountNotFound", "Account not found.", 404)
    if body.get("confirm") != account["handle"]:
        return error("ConfirmMismatch", "Confirmation does not match account handle.", 400)

    await directory.deactivate_account(env.db, account["did"])
    result = await env.account(account["do_id"]).takedown(did=account["did"])
    await agentbus.delete_agents_for_did(env.db, account["did"])
    await agentbus.delete_procs_for_did(env.db, account["did"])

    claims = request.access_claims
    actor = next(
        (claims[name] for name in ("email", "common_name") if isinstance(claims.get(name), str) and claims[name]),
        str(claims.get("sub")),
    )
    await directory.finalize_takedown(
        env.db, account["did"], account["handle"], actor,
        result["recordsDeleted"], result["blobsDeleted"], result["collections"],
    )
    summary = {
        "did": account["did"],
        "handle": account["handle"],
        "recordsDeleted": result["recordsDeleted"],
        "blobsDeleted": result["blobsDeleted"],
        "collections": result["collections"],
    }
    alert_takedown(env, dict(summary, actor=actor))
    return json_response(summary)


# Enrollment and identity

async def check_handle_name(env, name: str, did: str | None = None) -> str:
    """The full handle for `name` under this PDS's policy; raises AuthFailure with the 4xx otherwise.
    `did` may keep the handle it already holds (identity sync re-points it)."""
    if "." in name:
        raise AuthFailure(error("InvalidHandle", "Invalid handle: submit a single name without dots.", 400))
    handle = name + env.ROOKERY_HANDLE_DOMAIN
    try:
        ensure_valid_handle(handle)
    except InvalidHandleError as exc:
        raise AuthFailure(error("InvalidHandle", f"Invalid handle: {exc}", 400)) from exc
    if is_reserved_or_blocked(name):
        raise AuthFailure(error("HandleReserved", "Handle is reserved. Choose a different name.", 400))
    await directory.init_directory(env.db)
    owner = await directory.handle_owner(env.db, handle)
    if owner is not None and owner != did:
        raise AuthFailure(error("HandleTaken", "Handle is already taken. Choose another name.", 409))
    return handle


async def provision_account(env, handle: str, invite: str | None, jwk_thumbprint: str | None) -> str:
    """Create a did:plc, its Account DO and directory row for a checked handle; returns the DID.
    Spends `invite` when given. Raises AuthFailure for a spent invite or a taken handle."""
    signing = Secp256k1Keypair.create()
    rotation = Secp256k1Keypair.create()
    kem = P256Keypair()
    if invite and not await directory.spend_invite_pending(env.db, invite):
        raise AuthFailure(error("InviteInvalid", "Invite is invalid or already spent.", 403))
    try:
        did = await identity.create_plc_did(
            env.http, handle, env.ROOKERY_HOSTNAME, signing, rotation, env.ROOKERY_PLC_URL,
            env.ROOKERY_AGENTBUS_ENDPOINT, kem.did(),
        )
        do_id = env.new_account_id()
        await env.account(do_id).init_account(
            did=did, handle=handle,
            signing_key_hex=signing.export_hex(), signing_key_pub=signing.did().split(":")[-1],
            rotation_key_hex=rotation.export_hex(), rotation_key_pub=rotation.did().split(":")[-1],
            jwk_thumbprint=jwk_thumbprint, kem_key_hex=kem.export_hex(),
        )
        await directory.insert_account(env.db, did, handle, do_id, jwk_thumbprint)
    except Exception as exc:
        if invite:
            await directory.unspend_invite(env.db, invite, "pending")
        if "UNIQUE constraint failed" in str(exc):
            raise AuthFailure(error("HandleTaken", "Handle is already taken. Choose another name.", 409)) from exc
        raise

    await publish_handle_dns(env, handle, did)
    if invite and not await directory.finalize_invite_spend(env.db, invite, did):
        raise RuntimeError("Invite spend finalization failed")
    sync_knot_member(env, did)
    return did


async def check_signup_invite(env, ref) -> str | None:
    """The invite token an agent signup spends: required on commons, None elsewhere.
    Raises AuthFailure for a missing or spent invite."""
    if not is_commons(env):
        return None
    await directory.init_directory(env.db)
    invite = _extract_invite_token(ref)
    if not invite:
        raise AuthFailure(error("InviteRequired", "A valid invite ref is required for enrollment.", 403))
    if not await directory.is_invite_available(env.db, invite):
        raise AuthFailure(error("InviteInvalid", "Invite is invalid or already spent.", 403))
    return invite


@router.post("/api/signup")
async def signup(request, env):
    body = await read_json(request)
    if body is None:
        return invalid_json()
    submitted = body.get("handle")
    if not submitted or not isinstance(submitted, str):
        return error("InvalidRequest", "Missing or invalid handle", 400)
    if not body.get("tos_signature") or not isinstance(body["tos_signature"], str):
        return error("InvalidRequest", "Missing tos_signature", 400)
    if not body.get("access_token") or not isinstance(body["access_token"], str):
        return error("InvalidRequest", "Missing access_token", 400)
    dpop = request.header("dpop")
    if not dpop:
        return error("AuthRequired", "Missing DPoP proof", 401)
    try:
        proof = validate_dpop_proof(dpop, "POST", public_request_url(request, env), None)
    except AuthError as exc:
        return error("AuthFailed", str(exc), 401)

    terms = tos_text(env.ROOKERY_VARIANT)
    if not rs256_verify(proof["key"], body["tos_signature"], terms):
        return error("InvalidSignature", "Invalid ToS signature", 400)
    try:
        validate_access_token(body["access_token"], proof["key"], f"https://{request_host(request, env)}", proof["thumbprint"], terms)
    except AuthError as exc:
        return error("InvalidToken", str(exc), 400)

    invite = await check_signup_invite(env, body.get("ref"))
    handle = await check_handle_name(env, submitted.lower())
    did = await provision_account(env, handle, invite, proof["thumbprint"])
    return json_response({"did": did, "handle": handle, "access_token": body["access_token"], "token_type": "DPoP"})


async def _repoint_identity(env, did: str, do_id: str, handle: str) -> None:
    """Publish `handle`, this host and the account's #atproto_kem key (made now for
    an account that predates them) to PLC, then record it in the DO, D1 and DNS."""
    account = env.account(do_id)

    async def sign(data: bytes) -> dict:
        return await account.sign_with_rotation_key(data=data)

    await identity.update_plc_handle(
        env.http, did, handle, origin(env), sign, env.ROOKERY_PLC_URL, env.ROOKERY_AGENTBUS_ENDPOINT,
        await account.space_kem_key(create=True),
    )
    await account.set_handle(handle=handle)
    await directory.update_account_handle(env.db, did, handle)
    await publish_handle_dns(env, handle, did)


def _requested_name(env, handle: str) -> str:
    requested = handle.lower()
    domain = env.ROOKERY_HANDLE_DOMAIN
    if not requested.endswith(domain):
        raise AuthFailure(error("UnsupportedDomain", f"Handle must end with {domain}", 400))
    return requested[: len(requested) - len(domain)]


@router.post("/xrpc/com.atproto.identity.updateHandle")
async def update_handle(request, env):
    auth = await authenticate(request, env, "POST")
    if auth["kind"] == "oauth":
        granted = auth["scope"].split(" ")
        if "identity:handle" not in granted and "identity:*" not in granted:
            return error("InsufficientScope", "Scope does not permit identity:handle", 403)
    body = await read_json(request)
    if body is None:
        return invalid_json()
    if not isinstance(body.get("handle"), str):
        return error("InvalidRequest", "Missing required field: handle", 400)
    handle = await check_handle_name(env, _requested_name(env, body["handle"]))
    await _repoint_identity(env, auth["did"], auth["do_id"], handle)
    return body_response()


# Operator routes

def check_operator(request, env) -> Response | None:
    """Bearer token whose SHA-256 is ROOKERY_OPERATOR_TOKEN_SHA256; the routes don't exist when unset."""
    expected = (env.ROOKERY_OPERATOR_TOKEN_SHA256 or "").lower()
    if not expected:
        return not_found()
    match = re.match(r"^Bearer\s+(.+)$", request.header("authorization") or "", re.IGNORECASE | re.DOTALL)
    presented = sha256_hex(match.group(1) if match else "")
    if not hmac.compare_digest(presented, expected):
        return error("AccessDenied", "Access denied.", 403)
    return None


@router.post("/operator/identity/sync")
async def operator_identity_sync(request, env):
    denied = check_operator(request, env)
    if denied:
        return denied
    body = await read_json(request)
    if body is None:
        return invalid_json()
    did, handle = body.get("did"), body.get("handle")
    if not isinstance(did, str) or not isinstance(handle, str):
        return error("InvalidRequest", "Missing required fields: did, handle", 400)
    name = _requested_name(env, handle)
    resolved = await resolve_or_404(env, did, "AccountNotFound", "No account for this DID")
    full = await check_handle_name(env, name, did)
    await _repoint_identity(env, did, resolved["do_id"], full)
    return json_response({"did": did, "handle": full, "pds": origin(env)})


async def _list_all_records(account, collection: str) -> list[tuple[str, object]]:
    out, cursor = [], None
    while True:
        page = await account.list_records(collection=collection, limit=100, cursor=cursor)
        out += [(record["uri"].rsplit("/", 1)[1], record["value"]) for record in page["records"]]
        cursor = page.get("cursor")
        if not cursor:
            return out


@router.get("/operator/account/export")
async def operator_export(request, env):
    denied = check_operator(request, env)
    if denied:
        return denied
    did = request.query("did")
    if not did:
        return error("InvalidRequest", "Missing required parameter: did", 400)
    resolved = await resolve_or_404(env, did, "AccountNotFound", "No account for this DID")
    dump = await env.account(resolved["do_id"]).export_account()
    blob_bytes = {}
    for blob in dump["blobs"]:
        found = await env.blobs.get(f"{dump['state']['did']}/{blob['cid']}")
        if found is None:
            raise RuntimeError(f"Blob {blob['cid']} is missing from storage")
        blob_bytes[blob["cid"]] = found[0]
    return body_response(cbor.encode(dict(dump, blobBytes=blob_bytes)), 200, "application/cbor")


@router.post("/operator/account/import")
async def operator_import(request, env):
    denied = check_operator(request, env)
    if denied:
        return denied
    bad = error("InvalidRequest", "Body must be a CBOR account export", 400)
    try:
        data = cbor.decode(await request.bytes())
    except Exception:
        return bad
    state = data.get("state") if isinstance(data, dict) else None
    if (
        not isinstance(state, dict) or not isinstance(state.get("did"), str) or not state["did"].startswith("did:")
        or not isinstance(state.get("handle"), str) or not all(
            isinstance(data.get(name), list) for name in ("blocks", "blobs", "collections"))
    ):
        return bad
    did, handle = state["did"], state["handle"]
    await directory.init_directory(env.db)
    if await directory.account_exists(env.db, did, handle):
        return error("AccountExists", f"{did} or {handle} is already on this host", 409)

    blob_bytes = data.get("blobBytes") or {}
    for blob in data["blobs"]:
        raw = blob_bytes.get(blob["cid"])
        if raw is None:
            raise RepoError(f"Export is missing the bytes of blob {blob['cid']}")
        await env.blobs.put(f"{did}/{blob['cid']}", bytes(raw), blob["mime_type"])
    do_id = env.new_account_id()
    account = env.account(do_id)
    await account.import_account(dump={key: value for key, value in data.items() if key != "blobBytes"})
    await directory.insert_account(env.db, did, handle, do_id, state.get("jwk_thumbprint"))
    if state.get("active") != 1:
        await directory.deactivate_account(env.db, did)

    # Rebuild the agentbus index from the imported records.
    agents = [
        {"kind": "put", "rkey": rkey, "record": agentbus.validate_agent_record(rkey, value)}
        for rkey, value in await _list_all_records(account, agentbus.AGENT_COLLECTION)
    ]
    procs = [
        {"kind": "put", "rkey": rkey, "record": agentbus.validate_proc_record(rkey, value)}
        for rkey, value in await _list_all_records(account, agentbus.PROC_COLLECTION)
    ]
    await agentbus.apply_agent_index(env.db, did, agents)
    await agentbus.apply_proc_index(env.db, did, procs)
    return json_response({
        "did": did, "handle": handle, "rev": state.get("rev"), "blocks": len(data["blocks"]),
        "blobs": len(data["blobs"]), "agents": len(agents), "procs": len(procs),
    })


# Public reads

@router.get("/xrpc/com.atproto.identity.resolveHandle")
async def resolve_handle(request, env):
    handle = request.query("handle")
    if not handle:
        return error("InvalidRequest", "Missing required parameter: handle", 400)
    resolved = await resolve_or_404(env, handle, "HandleNotFound", f"Handle not found: {handle}")
    return json_response({"did": resolved["did"]})


@router.get("/xrpc/com.atproto.repo.getRecord")
async def get_record(request, env):
    repo, collection, rkey = (request.query(name) for name in ("repo", "collection", "rkey"))
    if not repo or not collection or not rkey:
        return error("InvalidRequest", "Missing required parameters: repo, collection, rkey", 400)
    resolved = await resolve_or_404(env, repo)
    found = await env.account(resolved["do_id"]).get_record(collection=collection, rkey=rkey)
    uri = f"at://{resolved['did']}/{collection}/{rkey}"
    if not found:
        # 400, as the reference PDS answers; clients such as Colibri treat it as "no record yet".
        return error("RecordNotFound", f"Could not locate record: {uri}", 400)
    return json_response({"uri": uri, "cid": found["cid"], "value": found["record"]})


@router.get("/xrpc/com.atproto.repo.listRecords")
async def list_records(request, env):
    repo, collection = request.query("repo"), request.query("collection")
    if not repo or not collection:
        return error("InvalidRequest", "Missing required parameters: repo, collection", 400)
    limit = clamp(request.query("limit"), 50, 100)
    resolved = await resolve_or_404(env, repo)
    return json_response(await env.account(resolved["do_id"]).list_records(
        collection=collection, limit=limit, cursor=request.query("cursor") or None,
        reverse=request.query("reverse") == "true",
    ))


@router.get("/xrpc/com.atproto.repo.describeRepo")
async def describe_repo(request, env):
    repo = request.query("repo")
    if not repo:
        return error("InvalidRequest", "Missing required parameter: repo", 400)
    resolved = await resolve_or_404(env, repo)
    described = await env.account(resolved["do_id"]).describe_repo()
    try:
        did_doc = await resolve_did_doc(env, described["did"])
    except IdentityError as exc:
        return error("InvalidRequest", f"Could not resolve DID: {exc}", 400)
    handle_is_correct = f"at://{described['handle']}" in (did_doc.get("alsoKnownAs") or [])
    return json_response(dict(described, didDoc=did_doc, handleIsCorrect=handle_is_correct))


@router.get("/xrpc/com.atproto.sync.listRepos")
async def list_repos(request, env):
    await directory.init_directory(env.db)
    limit = clamp(request.query("limit"), 500, 1000)
    cursor = request.query("cursor")
    if cursor:
        rows = await env.db.all(
            "SELECT did, active, do_id FROM accounts WHERE active = 1 AND did > ? ORDER BY did ASC LIMIT ?", cursor, limit
        )
    else:
        rows = await env.db.all("SELECT did, active, do_id FROM accounts WHERE active = 1 ORDER BY did ASC LIMIT ?", limit)
    commits = await asyncio.gather(*(env.account(row["do_id"]).get_latest_commit() for row in rows))
    repos = [
        {"did": row["did"], "head": commit["cid"], "rev": commit["rev"], "active": row["active"] == 1}
        for row, commit in zip(rows, commits) if commit
    ]
    body = {"repos": repos}
    if len(rows) == limit:
        body["cursor"] = rows[-1]["did"]
    return json_response(body)


@router.get("/xrpc/com.atproto.server.describeServer")
async def describe_server(request, env):
    await directory.init_directory(env.db)
    count = await env.db.first("SELECT COUNT(*) AS count FROM accounts WHERE active = 1")
    return json_response({
        "did": f"did:web:{env.ROOKERY_HOSTNAME}",
        "availableUserDomains": [env.ROOKERY_HANDLE_DOMAIN.removeprefix(".")],
        "inviteCodeRequired": is_commons(env),
        "phoneVerificationRequired": False,
        "links": {"termsOfService": f"{origin(env)}/tos"},
        "contact": {},
        "accounts": count["count"] if count else 0,
        "spacesAlpha": True,
    })


DESCRIBE_NSID = "community.lexicon.service.describe"


@router.get("/xrpc/" + DESCRIBE_NSID)
async def describe_service(request, env):
    """The XRPC methods this server implements, read from the route table (Spaces clients such as Colibri check it)."""
    methods = sorted({
        regex.pattern[len("^/xrpc/"):-1]
        for _, regex, _ in router.routes
        if regex.pattern.startswith("^/xrpc/") and is_valid_nsid(regex.pattern[len("^/xrpc/"):-1])
    })
    return json_response({
        "roles": ["pds"],
        "methods": [{"$type": f"{DESCRIBE_NSID}#nsid", "value": nsid} for nsid in methods],
    })


async def _list_registry(request, env, key: str, lister, filters: dict):
    limit = agentbus.clamp_list_limit(request.query("limit"))
    if limit is None:
        return error("InvalidRequest", "limit must be a positive integer", 400)
    raw_cursor = request.query("cursor")
    cursor = agentbus.decode_cursor(raw_cursor) if raw_cursor else None
    if raw_cursor and cursor is None:
        return error("InvalidRequest", "Invalid cursor", 400)
    await directory.init_directory(env.db)
    items = await lister(
        env.db, limit, did=request.query("did") or None, cursor=cursor,
        **{name: request.query(param) or None for name, param in filters.items()},
    )
    body = {key: items}
    if len(items) == limit:
        body["cursor"] = agentbus.encode_cursor(items[-1]["did"], items[-1]["name"])
    return json_response(body)


@router.get("/xrpc/org.latha.agentbus.listAgents")
async def list_agents(request, env):
    return await _list_registry(request, env, "agents", agentbus.list_agents,
                                {"capability": "capability", "task_class": "taskClass"})


@router.get("/xrpc/org.latha.agentbus.listProcs")
async def list_procs(request, env):
    return await _list_registry(request, env, "procs", agentbus.list_procs, {"fn": "function", "topic": "topic"})


@router.get("/.well-known/atproto-did")
async def atproto_did(request, env):
    # The edge proxy forwards the handle host here; the answer is public either way.
    host = request.header("x-forwarded-host") or request.header("host")
    if not host:
        return text_response("", 400)
    await directory.init_directory(env.db)
    try:
        resolved = await directory.resolve_repo(env.db, host.split(":")[0])
    except directory.RepoNotFoundError:
        return text_response("", 404)
    return text_response(resolved["did"])


# Authenticated session reads

@router.get("/xrpc/com.atproto.server.getSession")
async def get_session(request, env):
    auth = await authenticate(request, env, "GET")
    await directory.init_directory(env.db)
    row = await env.db.first("SELECT did, handle FROM accounts WHERE did = ? AND active = 1", auth["did"])
    if not row:
        return error("AccountNotFound", "No account for this session", 401)
    return json_response({"did": row["did"], "handle": row["handle"], "active": True})


@router.get("/xrpc/com.atproto.server.checkAccountStatus")
async def check_account_status(request, env):
    auth = await authenticate(request, env, "GET")
    status = await env.account(auth["do_id"]).account_status()
    try:
        doc = await resolve_did_doc(env, status["did"], force_refresh=True)
    except IdentityError:
        doc = None
    return json_response({
        "activated": status["active"],
        "validDid": doc is not None and _did_doc_matches(doc, status, origin(env)),
        "repoCommit": status["root_cid"],
        "repoRev": status["rev"],
        "repoBlocks": status["blocks"],
        "indexedRecords": status["records"],
        "privateStateValues": 0,
        "expectedBlobs": status["blobs"],
        "importedBlobs": status["blobs"],
    })


def _did_doc_matches(doc: dict, status: dict, pds_endpoint: str) -> bool:
    """The DID document names this PDS and the account's signing key."""
    return (
        doc_service_endpoint(doc, "atproto_pds") == pds_endpoint
        and doc_signing_key(doc) == status["signing_did"]
    )


@router.get("/xrpc/com.atproto.identity.getRecommendedDidCredentials")
async def get_recommended_did_credentials(request, env):
    auth = await authenticate(request, env, "GET")
    account = env.account(auth["do_id"])
    status = await account.account_status()
    return json_response(identity.did_credentials(
        status["handle"], origin(env), status["signing_did"], status["rotation_did"], env.ROOKERY_AGENTBUS_ENDPOINT,
        await account.space_kem_key(),
    ))


@router.get("/xrpc/com.atproto.server.listAppPasswords")
async def list_app_passwords(request, env):
    await authenticate(request, env, "GET")
    return json_response({"passwords": []})  # roost has no app passwords


@router.get("/xrpc/com.atproto.server.getAccountInviteCodes")
async def get_account_invite_codes(request, env):
    await authenticate(request, env, "GET")
    return json_response({"codes": []})  # invites are operator-minted, never per-account


@router.get("/xrpc/com.atproto.server.getServiceAuth")
async def get_service_auth(request, env):
    aud, lxm = request.query("aud"), request.query("lxm")
    if not aud or not lxm:
        return error("InvalidRequest", "Missing required parameters: aud, lxm", 400)
    if not is_valid_aud(aud):
        return error("InvalidRequest", "aud must be a DID, optionally with a #service fragment", 400)
    if not is_valid_nsid(lxm):
        return error("InvalidRequest", "Invalid lxm NSID", 400)
    now = now_s()
    raw_exp = request.query("exp")
    try:
        exp = now + 60 if raw_exp is None else float(raw_exp.strip() or "0")
    except ValueError:
        exp = 0.5
    if not float(exp).is_integer() or exp <= now or exp > now + 300:
        return error("InvalidRequest", "exp must be a Unix timestamp within five minutes", 400)
    auth = await authenticate(request, env, "GET")
    if auth["kind"] == "oauth":
        denied = enforce_rpc_scope(auth["scope"], lxm, aud)
        if denied:
            return error("InsufficientScope", f"Scope does not permit {denied}", 403)
    return json_response(await env.account(auth["do_id"]).sign_service_auth(aud=aud, lxm=lxm, exp=int(exp)))


# Repo writes

def _check_agent_writes(writes: list) -> dict:
    """Validate agentbus registry writes before commit; returns the index updates."""
    try:
        agentbus.check_service_writes(writes)
        return {"agents": agentbus.collect_agent_writes(writes), "procs": agentbus.collect_proc_writes(writes)}
    except agentbus.InvalidAgentRecordError as exc:
        raise AuthFailure(error("InvalidRecord", str(exc), 400)) from exc


async def _apply_agentbus_index(env, did: str, writes: dict) -> None:
    await agentbus.apply_agent_index(env.db, did, writes["agents"])
    await agentbus.apply_proc_index(env.db, did, writes["procs"])


def _check_repo(body: dict, auth: dict) -> None:
    if ":" in body["repo"] and body["repo"] != auth["did"]:
        raise AuthFailure(error("InvalidRequest", "Repo DID does not match authenticated account", 400))


def _present(body: dict, *fields: str) -> bool:
    """JS truthiness for string fields; `record` only needs to be present."""
    return all(
        (field in body) if field == "record" else bool(body.get(field)) and body.get(field) != 0
        for field in fields
    )


@router.post("/xrpc/com.atproto.repo.uploadBlob")
async def upload_blob(request, env):
    if js_int(request.header("content-length"), 0) > MAX_BLOB_BYTES:
        return error("BlobTooLarge", "Blob exceeds 60MB limit", 400)
    auth = await authenticate(request, env, "POST")
    mime_type = request.header("content-type") or "application/octet-stream"
    require_scope(auth, "uploadBlob", [], mime_type)
    data = await request.bytes()
    if len(data) > MAX_BLOB_BYTES:
        return error("BlobTooLarge", "Blob exceeds 60MB limit", 400)
    cid = blob_cid(data)
    await env.blobs.put(f"{auth['did']}/{cid}", data, mime_type)
    await env.account(auth["do_id"]).insert_blob(cid=cid, mime_type=mime_type, size=len(data))
    return json_response({"blob": {"$type": "blob", "ref": {"$link": cid}, "mimeType": mime_type, "size": len(data)}})


@router.post("/xrpc/com.atproto.repo.createRecord")
async def create_record(request, env):
    auth = await authenticate(request, env, "POST")
    body = await read_json(request)
    if body is None:
        return invalid_json()
    if not _present(body, "repo", "collection", "record"):
        return error("InvalidRequest", "Missing required fields: repo, collection, record", 400)
    _check_repo(body, auth)
    require_scope(auth, "write", [(body["collection"], "create")])
    index = _check_agent_writes([{
        "$type": "com.atproto.repo.applyWrites#create", "collection": body["collection"],
        "rkey": body.get("rkey"), "value": body["record"],
    }])
    result = await env.account(auth["do_id"]).create_record(
        collection=body["collection"], rkey=body.get("rkey") or None, record=body["record"],
    )
    await _apply_agentbus_index(env, auth["did"], index)
    return json_response(result)


@router.post("/xrpc/com.atproto.repo.putRecord")
async def put_record(request, env):
    auth = await authenticate(request, env, "POST")
    body = await read_json(request)
    if body is None:
        return invalid_json()
    if not _present(body, "repo", "collection", "rkey", "record"):
        return error("InvalidRequest", "Missing required fields: repo, collection, rkey, record", 400)
    _check_repo(body, auth)
    # putRecord creates or replaces, so it needs both.
    require_scope(auth, "write", [(body["collection"], "create"), (body["collection"], "update")])
    index = _check_agent_writes([{
        "$type": "com.atproto.repo.applyWrites#update", "collection": body["collection"],
        "rkey": body["rkey"], "value": body["record"],
    }])
    result = await env.account(auth["do_id"]).put_record(
        collection=body["collection"], rkey=body["rkey"], record=body["record"],
    )
    await _apply_agentbus_index(env, auth["did"], index)
    return json_response(result)


@router.post("/xrpc/com.atproto.repo.deleteRecord")
async def delete_record(request, env):
    auth = await authenticate(request, env, "POST")
    body = await read_json(request)
    if body is None:
        return invalid_json()
    if not _present(body, "repo", "collection", "rkey"):
        return error("InvalidRequest", "Missing required fields: repo, collection, rkey", 400)
    _check_repo(body, auth)
    require_scope(auth, "write", [(body["collection"], "delete")])
    result = await env.account(auth["do_id"]).delete_record(collection=body["collection"], rkey=body["rkey"])
    removal = [{"kind": "delete", "rkey": body["rkey"]}]
    if body["collection"] == agentbus.AGENT_COLLECTION:
        await agentbus.apply_agent_index(env.db, auth["did"], removal)
    elif body["collection"] == agentbus.PROC_COLLECTION:
        await agentbus.apply_proc_index(env.db, auth["did"], removal)
    return json_response(result)


@router.post("/xrpc/com.atproto.repo.applyWrites")
async def apply_writes(request, env):
    auth = await authenticate(request, env, "POST")
    body = await read_json(request)
    if body is None:
        return invalid_json()
    writes = body.get("writes")
    if not body.get("repo") or not isinstance(writes, list):
        return error("InvalidRequest", "Missing required fields: repo, writes", 400)
    if not all(isinstance(write, dict) for write in writes):
        return error("InvalidRequest", "Each write must be an object", 400)
    _check_repo(body, auth)
    require_scope(auth, "write", [(write.get("collection"), WRITE_ACTIONS.get(write.get("$type"))) for write in writes])
    index = _check_agent_writes(writes)
    result = await env.account(auth["do_id"]).apply_writes(writes=writes)
    await _apply_agentbus_index(env, auth["did"], index)
    return json_response(result)


# Sync

@router.get("/xrpc/com.atproto.sync.getBlob")
async def get_blob(request, env):
    did, cid = request.query("did"), request.query("cid")
    if not did or not cid:
        return error("InvalidRequest", "Missing required parameters: did, cid", 400)
    found = await env.blobs.get(f"{did}/{cid}")
    if found is None:
        return error("BlobNotFound", "Blob not found", 404)
    data, content_type = found
    return body_response(data, 200, content_type)


@router.get("/xrpc/com.atproto.sync.listBlobs")
async def list_blobs(request, env):
    did = request.query("did")
    if not did:
        return error("InvalidRequest", "Missing required parameter: did", 400)
    resolved = await resolve_or_404(env, did)
    limit = clamp(request.query("limit"), 500, 1000)
    return json_response(await env.account(resolved["do_id"]).list_blobs(limit=limit, cursor=request.query("cursor") or None))


@router.get("/xrpc/com.atproto.sync.getRepo")
async def get_repo(request, env):
    did = request.query("did")
    if not did:
        return error("InvalidRequest", "Missing required parameter: did", 400)
    resolved = await resolve_or_404(env, did)
    car = await env.account(resolved["do_id"]).export_repo()
    return body_response(car, 200, "application/vnd.ipld.car")


MAX_GET_BLOCKS = 1000


@router.get("/xrpc/com.atproto.sync.getBlocks")
async def get_blocks(request, env):
    did, cids = request.query("did"), request.query_all("cids")
    if not did or not cids:
        return error("InvalidRequest", "Missing required parameters: did, cids", 400)
    if len(cids) > MAX_GET_BLOCKS:
        return error("InvalidRequest", f"At most {MAX_GET_BLOCKS} cids per request", 400)
    try:
        cids = [str(CID.parse(cid)) for cid in cids]
    except ValueError:
        return error("InvalidRequest", "Invalid cid", 400)
    resolved = await resolve_or_404(env, did)
    car = await env.account(resolved["do_id"]).get_blocks(cids=cids)
    return body_response(car, 200, "application/vnd.ipld.car")


@router.get("/xrpc/com.atproto.sync.getLatestCommit")
async def get_latest_commit(request, env):
    did = request.query("did")
    if not did:
        return error("InvalidRequest", "Missing required parameter: did", 400)
    resolved = await resolve_or_404(env, did)
    commit = await env.account(resolved["do_id"]).get_latest_commit()
    return json_response(commit) if commit else error("RepoNotFound", "Repository not found", 404)


@router.get("/xrpc/com.atproto.sync.getRepoStatus")
async def get_repo_status(request, env):
    did = request.query("did")
    if not did:
        return error("InvalidRequest", "Missing required parameter: did", 400)
    resolved = await resolve_or_404(env, did)
    status = await env.account(resolved["do_id"]).get_repo_status()
    return json_response(status) if status else error("RepoNotFound", "Repository not found", 404)


@router.get("/xrpc/com.atproto.sync.subscribeRepos")
async def subscribe_repos(request, env):
    return await env.subscribe_repos(request)


# Route modules that register on `router`.
from .spaces import routes as _space_routes  # noqa: E402,F401
from .humans import routes as _human_routes  # noqa: E402,F401
from .humans import account as _account_routes  # noqa: E402,F401
from .mcp import routes as _mcp_routes  # noqa: E402,F401
from .humans import proxy as _proxy_routes  # noqa: E402,F401  (last: catches unserved /xrpc methods)
