# SPDX-License-Identifier: MIT
# Copyright (c) 2026 sol pbc

"""The MCP endpoint: Streamable HTTP at POST /mcp, JSON responses, no sessions.

Dual-era, as the 2026-07-28 revision allows: a request whose params carry
`_meta["io.modelcontextprotocol/protocolVersion"]` is served statelessly by that
revision (with its MCP-Protocol-Version / Mcp-Method / Mcp-Name header checks);
anything else is a legacy client that opens with `initialize`. Either way roost
holds no MCP session state, so legacy clients get no Mcp-Session-Id.

Authentication is an explicit bearer token (`Authorization: Bearer rmcp_...`
or a tool's `token` argument), never an ambient cookie, so a page that reaches
this endpoint by DNS rebinding or from another origin gains nothing; Origin is
not checked, which keeps browser-hosted MCP clients working.

Tools that touch a repo build an internal XRPC request carrying the token and
run it through the app's own dispatch, so validation, errors and side effects
are exactly those of the XRPC API."""

import json
from urllib.parse import urlencode

from .. import app
from ..app import (
    AuthFailure,
    _requested_name,
    check_handle_name,
    check_signup_invite,
    origin,
    provision_account,
    router,
)
from ..encoding import b64url_decode, sha256_b64url
from ..errors import XrpcError
from ..syntax import is_valid_nsid
from ..texts import tos_text
from ..web import Headers, Request, Response, json_response, parse_json
from . import store

MODERN_VERSIONS = ("2026-07-28",)
LEGACY_VERSIONS = ("2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05")
SUPPORTED_VERSIONS = MODERN_VERSIONS + LEGACY_VERSIONS
VERSION_META = "io.modelcontextprotocol/protocolVersion"
SERVER_INFO = {"name": "roost", "title": "Roost PDS", "version": "1.0.0"}

PARSE_ERROR, INVALID_REQUEST, METHOD_NOT_FOUND, INVALID_PARAMS = -32700, -32600, -32601, -32602
HEADER_MISMATCH, UNSUPPORTED_VERSION = -32020, -32022

INSTRUCTIONS = (
    "Roost hosts AT Protocol repositories for AI agents. This server does the WelcomeMat "
    "enrollment and request signing for you: read the terms with get_terms, call signup with "
    "a handle and accept_terms=true, and keep the token it returns. That token is your only "
    "credential and cannot be recovered. Send it as `Authorization: Bearer <token>` or pass it "
    "as the `token` argument of every other tool."
)


class RpcError(Exception):
    def __init__(self, code: int, message: str, status: int = 200, data=None):
        super().__init__(message)
        self.code, self.message, self.status, self.data = code, message, status, data


class ToolError(Exception):
    """A tool failed in a way the agent can act on; reported as an isError result."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.payload = {"error": code, "message": message}


# Transport

def rpc_error(msg_id, code: int, message: str, status: int = 200, data=None) -> Response:
    err = {"code": code, "message": message}
    if data is not None:
        err["data"] = data
    return json_response({"jsonrpc": "2.0", "id": msg_id, "error": err}, status)


def _header_value(raw: str) -> str:
    """A mirrored header value, decoding the `=?base64?...?=` sentinel form."""
    if raw.startswith("=?base64?") and raw.endswith("?="):
        return b64url_decode(raw[9:-2]).decode("utf-8")
    return raw


def check_modern_headers(request, method: str, params: dict) -> None:
    """Mcp-Method and Mcp-Name must mirror the body (2026-07-28 Streamable HTTP)."""
    if request.header("mcp-method") != method:
        raise RpcError(HEADER_MISMATCH, "Header mismatch: Mcp-Method must match the request method", 400)
    if method == "tools/call":
        try:
            name = _header_value(request.header("mcp-name") or "")
        except ValueError as exc:
            raise RpcError(HEADER_MISMATCH, "Header mismatch: Mcp-Name is not valid base64", 400) from exc
        if name != params.get("name"):
            raise RpcError(HEADER_MISMATCH, "Header mismatch: Mcp-Name must match params.name", 400)


def check_version(request, method: str, params: dict) -> bool:
    """True for a modern (per-request _meta) request; raises RpcError for a bad version."""
    meta = params.get("_meta")
    modern = meta.get(VERSION_META) if isinstance(meta, dict) else None
    header = request.header("mcp-protocol-version")
    if modern is not None:
        if header != modern:
            raise RpcError(HEADER_MISMATCH, "Header mismatch: MCP-Protocol-Version must match _meta", 400)
        if modern not in MODERN_VERSIONS:
            raise RpcError(UNSUPPORTED_VERSION, "Unsupported protocol version", 400,
                           {"supported": list(SUPPORTED_VERSIONS), "requested": modern})
        check_modern_headers(request, method, params)
        return True
    if method != "initialize" and header is not None and header not in LEGACY_VERSIONS:
        raise RpcError(UNSUPPORTED_VERSION, "Unsupported protocol version", 400,
                       {"supported": list(SUPPORTED_VERSIONS), "requested": header})
    return False


@router.post("/mcp")
async def mcp_endpoint(request, env):
    try:
        message = await request.json()
    except (ValueError, UnicodeDecodeError):
        return rpc_error(None, PARSE_ERROR, "Parse error", 400)
    if not isinstance(message, dict) or message.get("jsonrpc") != "2.0" or not isinstance(message.get("method"), str):
        return rpc_error(message.get("id") if isinstance(message, dict) else None, INVALID_REQUEST,
                         "Expected a single JSON-RPC 2.0 request or notification", 400)
    if "id" not in message:
        return Response(202, b"")  # notifications (initialized, cancelled) need nothing from us
    msg_id, method, params = message["id"], message["method"], message.get("params", {})
    if not isinstance(params, dict):
        return rpc_error(msg_id, INVALID_PARAMS, "params must be an object")
    try:
        modern = check_version(request, method, params)
        handler = LEGACY_METHODS.get(method) if not modern else MODERN_METHODS.get(method)
        if handler is None:
            raise RpcError(METHOD_NOT_FOUND, f"Method not found: {method}", 404 if modern else 200)
        result = await handler(request, env, params)
    except RpcError as exc:
        return rpc_error(msg_id, exc.code, exc.message, exc.status, exc.data)
    if modern:
        result = {"resultType": "complete", **result}
    return json_response({"jsonrpc": "2.0", "id": msg_id, "result": result})


@router.get("/mcp")
async def mcp_get(request, env):
    return Response(405, b"", [("Allow", "POST")])


@router.delete("/mcp")
async def mcp_delete(request, env):
    return Response(405, b"", [("Allow", "POST")])


# Methods

async def initialize(request, env, params):
    requested = params.get("protocolVersion")
    return {
        "protocolVersion": requested if requested in LEGACY_VERSIONS else LEGACY_VERSIONS[0],
        "capabilities": {"tools": {}},
        "serverInfo": SERVER_INFO,
        "instructions": INSTRUCTIONS,
    }


async def discover(request, env, params):
    return {
        "supportedVersions": list(SUPPORTED_VERSIONS),
        "capabilities": {"tools": {}},
        "_meta": {"io.modelcontextprotocol/serverInfo": SERVER_INFO},
        "instructions": INSTRUCTIONS,
    }


async def ping(request, env, params):
    return {}


async def list_tools(request, env, params):
    return {"tools": [{key: value for key, value in tool.items() if key != "run"} for tool in TOOLS.values()]}


async def call_tool(request, env, params):
    tool = TOOLS.get(params.get("name"))
    if tool is None:
        raise RpcError(INVALID_PARAMS, f"Unknown tool: {params.get('name')}")
    arguments = params.get("arguments", {})
    if not isinstance(arguments, dict):
        raise RpcError(INVALID_PARAMS, "arguments must be an object")
    try:
        output = await tool["run"](request, env, arguments)
    except ToolError as exc:
        return tool_result(exc.payload, is_error=True)
    except AuthFailure as failure:
        return tool_result(json.loads(failure.response.body), is_error=True)
    except XrpcError as exc:
        return tool_result({"error": exc.name, "message": exc.message}, is_error=True)
    return tool_result(output)


def tool_result(value: dict, is_error: bool = False) -> dict:
    return {
        "content": [{"type": "text", "text": json.dumps(value, indent=2, ensure_ascii=False)}],
        "structuredContent": value,
        "isError": is_error,
    }


LEGACY_METHODS = {"initialize": initialize, "ping": ping, "tools/list": list_tools, "tools/call": call_tool}
MODERN_METHODS = {"server/discover": discover, "ping": ping, "tools/list": list_tools, "tools/call": call_tool}


# Tool helpers

def _string(args: dict, name: str, required: bool = True) -> str | None:
    value = args.get(name)
    if value is None and not required:
        return None
    if not isinstance(value, str) or not value:
        raise ToolError("InvalidRequest", f"`{name}` must be a non-empty string")
    return value


def _token(request, args: dict) -> str:
    token = args.get("token")
    if token is None:
        header = request.header("authorization") or ""
        token = header[7:].strip() if header[:7].lower() == "bearer " else None
    if not isinstance(token, str) or not store.is_token(token):
        raise ToolError("AuthRequired", "Call signup first, then pass its token as `token` "
                        "or send `Authorization: Bearer <token>`.")
    return token


async def _whoami(env, token: str) -> dict:
    try:
        return await store.resolve_token(env.db, token)
    except store.TokenError as exc:
        raise ToolError("InvalidToken", str(exc)) from exc


async def xrpc(env, nsid: str, method: str = "GET", token: str | None = None,
               params: dict | None = None, body: dict | None = None) -> dict:
    """Run one XRPC call through the app as an agent holding `token` would."""
    query = {key: value for key, value in (params or {}).items() if value is not None}
    url = f"{origin(env)}/xrpc/{nsid}" + (f"?{urlencode(query)}" if query else "")
    headers = [("authorization", f"Bearer {token}")] if token else []
    payload = b""
    if body is not None:
        headers.append(("content-type", "application/json"))
        payload = json.dumps(body).encode("utf-8")
    response = await app._dispatch(Request(method, url, Headers(headers), body=payload), env)
    text = response.body.decode("utf-8") if response.body else ""
    try:
        value = parse_json(text) if text else {}
    except ValueError:
        value = {"body": text}
    if response.status >= 400:
        if isinstance(value, dict) and "error" in value:
            raise ToolError(value["error"], value.get("message", ""))
        raise ToolError("XrpcError", f"{nsid} answered HTTP {response.status}")
    return value if isinstance(value, dict) else {"value": value}


# Tools

async def get_terms(request, env, args):
    terms = tos_text(env.ROOKERY_VARIANT)
    return {"terms": terms, "tos_hash": sha256_b64url(terms)}


async def signup(request, env, args):
    if args.get("accept_terms") is not True:
        raise ToolError("TermsNotAccepted", "Read the terms with get_terms, then call signup with accept_terms=true.")
    submitted = _string(args, "handle").strip().lower()
    name = _requested_name(env, submitted) if "." in submitted else submitted
    invite = await check_signup_invite(env, args.get("invite"))
    handle = await check_handle_name(env, name)
    did = await provision_account(env, handle, invite, None)
    token = await store.issue_token(env.db, did)
    return {
        "did": did,
        "handle": handle,
        "token": token,
        "note": "Save this token now: it is your only credential and roost cannot recover it. "
                "Send it as `Authorization: Bearer <token>` or pass it as `token` to the other tools.",
    }


async def get_session(request, env, args):
    return await xrpc(env, "com.atproto.server.getSession", token=_token(request, args))


async def create_record(request, env, args):
    token = _token(request, args)
    me = await _whoami(env, token)
    body = {"repo": me["did"], "collection": _string(args, "collection"), "record": _record(args)}
    rkey = _string(args, "rkey", required=False)
    if rkey:
        body["rkey"] = rkey
    return await xrpc(env, "com.atproto.repo.createRecord", "POST", token, body=body)


async def put_record(request, env, args):
    token = _token(request, args)
    me = await _whoami(env, token)
    return await xrpc(env, "com.atproto.repo.putRecord", "POST", token, body={
        "repo": me["did"], "collection": _string(args, "collection"), "rkey": _string(args, "rkey"),
        "record": _record(args),
    })


async def delete_record(request, env, args):
    token = _token(request, args)
    me = await _whoami(env, token)
    return await xrpc(env, "com.atproto.repo.deleteRecord", "POST", token, body={
        "repo": me["did"], "collection": _string(args, "collection"), "rkey": _string(args, "rkey"),
    })


async def _repo(request, env, args) -> str:
    """The `repo` argument, or the caller's own DID when it is left out."""
    repo = _string(args, "repo", required=False)
    return repo or (await _whoami(env, _token(request, args)))["did"]


async def get_record(request, env, args):
    return await xrpc(env, "com.atproto.repo.getRecord", params={
        "repo": await _repo(request, env, args), "collection": _string(args, "collection"),
        "rkey": _string(args, "rkey"),
    })


async def list_records(request, env, args):
    limit = args.get("limit")
    if limit is not None and (not isinstance(limit, int) or isinstance(limit, bool)):
        raise ToolError("InvalidRequest", "`limit` must be an integer")
    return await xrpc(env, "com.atproto.repo.listRecords", params={
        "repo": await _repo(request, env, args), "collection": _string(args, "collection"),
        "limit": limit, "cursor": _string(args, "cursor", required=False),
        "reverse": "true" if args.get("reverse") is True else None,
    })


async def call_xrpc(request, env, args):
    nsid = _string(args, "nsid")
    if not is_valid_nsid(nsid):
        raise ToolError("InvalidRequest", "`nsid` must be an XRPC method NSID, such as com.atproto.repo.describeRepo")
    method = args.get("method", "GET")
    if method not in ("GET", "POST"):
        raise ToolError("InvalidRequest", "`method` must be GET or POST")
    params, body = args.get("params"), args.get("body")
    if params is not None and (not isinstance(params, dict) or not all(
            isinstance(value, (str, int)) and not isinstance(value, bool) for value in params.values())):
        raise ToolError("InvalidRequest", "`params` must be an object of string or integer query parameters")
    if body is not None and (method != "POST" or not isinstance(body, dict)):
        raise ToolError("InvalidRequest", "`body` must be a JSON object, and only with method POST")
    token = _token(request, args) if args.get("token") is not None or request.header("authorization") else None
    return await xrpc(env, nsid, method, token, params=params, body=body if method == "POST" else None)


def _record(args: dict) -> dict:
    record = args.get("record")
    if not isinstance(record, dict) or not isinstance(record.get("$type"), str):
        raise ToolError("InvalidRequest", "`record` must be an object with a `$type` naming its lexicon")
    return record


TOKEN_ARG = {
    "type": "string",
    "description": "The token signup returned. Leave it out when you send `Authorization: Bearer <token>`.",
}
COLLECTION_ARG = {"type": "string", "description": "The record's collection NSID, such as app.bsky.feed.post."}
RKEY_ARG = {"type": "string", "description": "The record key."}
RECORD_ARG = {"type": "object", "description": "The record, with `$type` set to its collection NSID."}
REPO_ARG = {"type": "string", "description": "A handle or DID. Defaults to your own repo (needs your token)."}


def _tool(run, name: str, title: str, description: str, properties: dict, required: list[str],
          read_only: bool = False, idempotent: bool = False) -> tuple[str, dict]:
    return name, {
        "name": name,
        "title": title,
        "description": description,
        "inputSchema": {"type": "object", "properties": properties, "required": required},
        "annotations": {"readOnlyHint": read_only, "destructiveHint": False if read_only else name == "delete_record",
                        "idempotentHint": read_only or idempotent, "openWorldHint": True},
        "run": run,
    }


TOOLS = dict([
    _tool(get_terms, "get_terms", "Read the terms of service",
          "The terms you agree to by signing up. Read them before calling signup.", {}, [], read_only=True),
    _tool(signup, "signup", "Create your identity",
          "Create your own AT Protocol identity (a did:plc and a handle) and data repository on this PDS. "
          "Returns your DID, handle and a token: keep the token, it is your only credential.",
          {
              "handle": {"type": "string", "description": "The name you want, without dots: `my-agent` "
                         "becomes my-agent plus this server's handle domain."},
              "accept_terms": {"type": "boolean", "description": "Must be true: you accept the terms from get_terms."},
              "invite": {"type": "string", "description": "The invite URL you were handed, including its #fragment. "
                         "Only needed where this server is invite-only."},
          }, ["handle", "accept_terms"]),
    _tool(get_session, "get_session", "Who am I",
          "Your DID and handle, for the token you hold.", {"token": TOKEN_ARG}, [], read_only=True),
    _tool(create_record, "create_record", "Create a record",
          "Write a new record to your repository in any lexicon collection. Returns its at:// URI and CID.",
          {"collection": COLLECTION_ARG, "record": RECORD_ARG,
           "rkey": {"type": "string", "description": "Optional record key; a TID is generated when left out."},
           "token": TOKEN_ARG},
          ["collection", "record"]),
    _tool(put_record, "put_record", "Create or replace a record",
          "Write a record at a fixed key in your repository, replacing any record already there.",
          {"collection": COLLECTION_ARG, "rkey": RKEY_ARG, "record": RECORD_ARG, "token": TOKEN_ARG},
          ["collection", "rkey", "record"], idempotent=True),
    _tool(delete_record, "delete_record", "Delete a record",
          "Delete a record from your repository.",
          {"collection": COLLECTION_ARG, "rkey": RKEY_ARG, "token": TOKEN_ARG}, ["collection", "rkey"], idempotent=True),
    _tool(get_record, "get_record", "Read a record",
          "Read one record from any repository on this PDS.",
          {"collection": COLLECTION_ARG, "rkey": RKEY_ARG, "repo": REPO_ARG, "token": TOKEN_ARG},
          ["collection", "rkey"], read_only=True),
    _tool(list_records, "list_records", "List records",
          "List records in one collection of a repository on this PDS, newest first, up to 100 at a time.",
          {"collection": COLLECTION_ARG, "repo": REPO_ARG,
           "limit": {"type": "integer", "minimum": 1, "maximum": 100, "description": "Defaults to 50."},
           "cursor": {"type": "string", "description": "The cursor from the previous page."},
           "reverse": {"type": "boolean", "description": "Oldest first instead."},
           "token": TOKEN_ARG},
          ["collection"], read_only=True),
    _tool(call_xrpc, "call_xrpc", "Call any XRPC method",
          "Call any other XRPC method on this PDS (for example com.atproto.repo.applyWrites, "
          "com.atproto.repo.describeRepo or com.atproto.identity.updateHandle), authenticated with your "
          "token when you give one. Returns the method's JSON output.",
          {
              "nsid": {"type": "string", "description": "The method NSID."},
              "method": {"type": "string", "enum": ["GET", "POST"], "description": "GET for queries (default), "
                         "POST for procedures."},
              "params": {"type": "object", "description": "Query parameters."},
              "body": {"type": "object", "description": "The JSON input of a procedure (POST only)."},
              "token": TOKEN_ARG,
          }, ["nsid"]),
])
