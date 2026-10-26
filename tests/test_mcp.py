# SPDX-License-Identifier: MIT
# Copyright (c) 2026 sol pbc

"""The MCP server at /mcp: legacy (initialize) and modern (per-request _meta)
clients, token signup, and the repo tools over the real XRPC routes."""

import base64
import itertools

from conftest import unique

_ids = itertools.count(1)
MODERN = "2026-07-28"


async def rpc(client, method, params=None, headers=None, raw=None):
    body = raw if raw is not None else {"jsonrpc": "2.0", "id": next(_ids), "method": method, "params": params or {}}
    headers = dict({"accept": "application/json, text/event-stream"}, **(headers or {}))
    return await client.post("/mcp", json_body=body, headers=headers)


async def call(client, name, arguments=None, headers=None):
    response = await rpc(client, "tools/call", {"name": name, "arguments": arguments or {}}, headers)
    assert response.status == 200, response.text
    return response.json()["result"]


async def mcp_signup(client, name=None):
    result = await call(client, "signup", {"handle": name or unique("mcp"), "accept_terms": True})
    assert result["isError"] is False, result
    return result["structuredContent"]


async def test_legacy_initialize_and_tool_list(client):
    response = await rpc(client, "initialize", {
        "protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "test", "version": "0"}})
    assert response.status == 200
    result = response.json()["result"]
    assert result["protocolVersion"] == "2025-06-18"
    assert result["capabilities"] == {"tools": {}}
    assert "mcp-session-id" not in response.headers

    unknown = await rpc(client, "initialize", {"protocolVersion": "1999-01-01"})
    assert unknown.json()["result"]["protocolVersion"] == "2025-11-25"

    initialized = await rpc(client, None, raw={"jsonrpc": "2.0", "method": "notifications/initialized"})
    assert initialized.status == 202 and initialized.body == b""

    tools = (await rpc(client, "tools/list", headers={"mcp-protocol-version": "2025-06-18"})).json()["result"]["tools"]
    names = {tool["name"] for tool in tools}
    assert {"get_terms", "signup", "get_session", "create_record", "put_record", "delete_record",
            "get_record", "list_records", "call_xrpc"} <= names
    assert all(tool["inputSchema"]["type"] == "object" and "run" not in tool for tool in tools)


async def test_modern_requests_are_stateless_and_check_headers(client):
    meta = {"_meta": {"io.modelcontextprotocol/protocolVersion": MODERN}}
    headers = {"mcp-protocol-version": MODERN, "mcp-method": "server/discover"}
    discover = await rpc(client, "server/discover", meta, headers)
    assert discover.status == 200
    assert MODERN in discover.json()["result"]["supportedVersions"]
    assert discover.json()["result"]["resultType"] == "complete"

    params = dict(meta, name="get_terms", arguments={})
    terms = await rpc(client, "tools/call", params, {
        "mcp-protocol-version": MODERN, "mcp-method": "tools/call",
        "mcp-name": "=?base64?" + base64.b64encode(b"get_terms").decode() + "?="})
    assert terms.status == 200 and terms.json()["result"]["resultType"] == "complete"
    assert "Terms of Service" in terms.json()["result"]["structuredContent"]["terms"]

    mismatch = await rpc(client, "tools/call", params, {
        "mcp-protocol-version": MODERN, "mcp-method": "tools/call", "mcp-name": "signup"})
    assert mismatch.status == 400 and mismatch.json()["error"]["code"] == -32020

    version = await rpc(client, "tools/list", meta, {"mcp-protocol-version": "2025-06-18", "mcp-method": "tools/list"})
    assert version.status == 400 and version.json()["error"]["code"] == -32020

    unsupported = await rpc(client, "tools/list", {"_meta": {"io.modelcontextprotocol/protocolVersion": "2099-01-01"}},
                            {"mcp-protocol-version": "2099-01-01", "mcp-method": "tools/list"})
    assert unsupported.status == 400 and unsupported.json()["error"]["code"] == -32022
    assert MODERN in unsupported.json()["error"]["data"]["supported"]

    missing = await rpc(client, "nope/nope", meta, {"mcp-protocol-version": MODERN, "mcp-method": "nope/nope"})
    assert missing.status == 404 and missing.json()["error"]["code"] == -32601


async def test_transport_rejects_what_it_does_not_serve(client):
    assert (await client.get("/mcp")).status == 405
    assert (await client.delete("/mcp")).status == 405
    garbage = await client.post("/mcp", body="{not json", headers={"content-type": "application/json"})
    assert garbage.status == 400 and garbage.json()["error"]["code"] == -32700
    batch = await client.post("/mcp", json_body=[{"jsonrpc": "2.0", "id": 1, "method": "ping"}])
    assert batch.status == 400 and batch.json()["error"]["code"] == -32600
    unknown_tool = await rpc(client, "tools/call", {"name": "nope"})
    assert unknown_tool.json()["error"]["code"] == -32602


async def test_signup_requires_accepting_the_terms(client):
    result = await call(client, "signup", {"handle": unique("mcp")})
    assert result["isError"] and result["structuredContent"]["error"] == "TermsNotAccepted"


async def test_signup_then_write_and_read_records(client, env):
    name = unique("mcp")
    account = await mcp_signup(client, name)
    assert account["handle"] == name + env.ROOKERY_HANDLE_DOMAIN
    assert account["did"].startswith("did:plc:") and account["token"].startswith("rmcp_")
    token = account["token"]

    session = await call(client, "get_session", {"token": token})
    assert session["structuredContent"]["did"] == account["did"]

    record = {"$type": "app.bsky.feed.post", "text": "hello from mcp", "createdAt": "2026-10-26T00:00:00Z"}
    created = await call(client, "create_record", {"collection": "app.bsky.feed.post", "record": record, "token": token})
    assert created["isError"] is False, created
    uri = created["structuredContent"]["uri"]
    rkey = uri.rsplit("/", 1)[1]
    assert uri.startswith(f"at://{account['did']}/app.bsky.feed.post/")

    # Reads go through the public XRPC route, by handle too.
    public = await client.get("/xrpc/com.atproto.repo.getRecord", params={
        "repo": account["handle"], "collection": "app.bsky.feed.post", "rkey": rkey})
    assert public.status == 200 and public.json()["value"]["text"] == "hello from mcp"
    got = await call(client, "get_record", {"collection": "app.bsky.feed.post", "rkey": rkey, "token": token})
    assert got["structuredContent"]["value"]["text"] == "hello from mcp"

    # The Authorization header works in place of the argument.
    bearer = {"authorization": f"Bearer {token}"}
    put = await call(client, "put_record", {"collection": "com.example.note", "rkey": "self",
                                            "record": {"$type": "com.example.note", "body": "v1"}}, bearer)
    assert put["isError"] is False, put
    listed = await call(client, "list_records", {"collection": "com.example.note"}, bearer)
    assert [entry["value"]["body"] for entry in listed["structuredContent"]["records"]] == ["v1"]

    deleted = await call(client, "delete_record", {"collection": "com.example.note", "rkey": "self"}, bearer)
    assert deleted["isError"] is False
    gone = await call(client, "get_record", {"collection": "com.example.note", "rkey": "self", "repo": account["did"]})
    assert gone["isError"] and gone["structuredContent"]["error"] == "RecordNotFound"

    described = await call(client, "call_xrpc", {"nsid": "com.atproto.repo.describeRepo",
                                                 "params": {"repo": account["did"]}})
    assert described["structuredContent"]["handle"] == account["handle"]


async def test_mcp_token_works_as_bearer_on_xrpc(client):
    account = await mcp_signup(client)
    response = await client.get("/xrpc/com.atproto.server.getSession",
                                headers={"authorization": f"Bearer {account['token']}"})
    assert response.status == 200 and response.json()["did"] == account["did"]
    forged = await client.get("/xrpc/com.atproto.server.getSession", headers={"authorization": "Bearer rmcp_forged"})
    assert forged.status == 401 and forged.json()["error"] == "InvalidToken"


async def test_writes_need_a_valid_token(client):
    record = {"$type": "app.bsky.feed.post", "text": "x"}
    anonymous = await call(client, "create_record", {"collection": "app.bsky.feed.post", "record": record})
    assert anonymous["isError"] and anonymous["structuredContent"]["error"] == "AuthRequired"
    forged = await call(client, "create_record", {"collection": "app.bsky.feed.post", "record": record, "token": "rmcp_x"})
    assert forged["isError"] and forged["structuredContent"]["error"] == "InvalidToken"
    untyped = await call(client, "create_record", {"collection": "app.bsky.feed.post", "record": {"text": "x"},
                                                   "token": (await mcp_signup(client))["token"]})
    assert untyped["isError"] and untyped["structuredContent"]["error"] == "InvalidRequest"


async def test_signup_reports_taken_and_invalid_handles(client, enroll):
    rook = await enroll()
    taken = await call(client, "signup", {"handle": rook.handle.split(".")[0], "accept_terms": True})
    assert taken["isError"] and taken["structuredContent"]["error"] == "HandleTaken"
    invalid = await call(client, "signup", {"handle": "bad_name!", "accept_terms": True})
    assert invalid["isError"] and invalid["structuredContent"]["error"] == "InvalidHandle"


async def test_welcome_mentions_the_mcp_server(client):
    assert "/mcp" in (await client.get("/.well-known/welcome.md")).text
