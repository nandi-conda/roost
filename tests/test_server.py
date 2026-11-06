# SPDX-License-Identifier: MIT
# Copyright (c) 2026 sol pbc

"""The FastAPI server (server/roost_server): HTTP and the firehose through a
real ASGI stack, the SQLite -> Postgres translation, outbound fetch limits,
and the blob stores. (The whole suite also runs on the server's storage with
ROOST_TEST_BACKEND=sqlite|postgres; see server_env.py.)"""

import asyncio
import os
from urllib.parse import urlsplit, urlunsplit

import pytest
from starlette.testclient import TestClient, WebSocketDenialResponse

from agent import Agent
from fakes import DEFAULT_VARS, Http, Plc
from roost import cbor
from roost_server.app import _static, build_env, create_app
from roost_server.blobs import DirectoryBlobs, PostgresBlobs, S3Blobs
from roost_server.platform import Http as ServerHttp
from roost_server.sql import SqliteBackend, check_account_id, to_postgres
from server_env import MemoryBlobs

ORIGIN = "https://rookery.test"
FIREHOSE = "/xrpc/com.atproto.sync.subscribeRepos"


def frame(data: bytes) -> tuple[dict, dict]:
    header, end = cbor.decode_first(data)
    return header, cbor.decode_first(data, end)[0]


@pytest.fixture
def server(tmp_path):
    public = tmp_path / "public"
    (public / "dashboard").mkdir(parents=True)
    (public / "dashboard" / "index.html").write_text("<p>dashboard</p>")
    (public / "dashboard" / "app.js").write_text("ok()")
    http = Http()
    plc = Plc()
    http.routes[DEFAULT_VARS["ROOKERY_PLC_URL"]] = plc
    env = build_env(dict(DEFAULT_VARS), backend=SqliteBackend(":memory:"), blob_store=MemoryBlobs(), http=http)
    with TestClient(create_app(env=env, public_dir=public), base_url=ORIGIN) as client:
        yield client


def signup(client: TestClient, name: str) -> tuple[Agent, dict]:
    tos = client.get("/tos").text
    agent = Agent(ORIGIN, tos)
    agent.access_token = agent.make_access_token()
    response = client.post("/api/signup", json=agent.signup_body(name),
                           headers={"DPoP": agent.dpop("POST", "/api/signup")})
    assert response.status_code == 200, response.text
    return agent, response.json()


def create_post(client: TestClient, agent: Agent, did: str, text: str):
    path = "/xrpc/com.atproto.repo.createRecord"
    response = client.post(path, json={"repo": did, "collection": "app.bsky.feed.post", "record": {"text": text}},
                           headers=agent.auth_headers("POST", path))
    assert response.status_code == 200, response.text
    return response.json()


# HTTP

def test_requests_reach_roost_with_cors_and_no_fastapi_extras(server):
    described = server.get("/xrpc/com.atproto.server.describeServer")
    assert described.status_code == 200 and described.json()["did"] == "did:web:rookery.test"
    assert described.headers["access-control-allow-origin"] == "*"
    assert server.get("/docs").status_code == 404 and server.get("/openapi.json").status_code == 404
    assert server.get("/nope").text == "404 Not Found"
    preflight = server.options("/xrpc/x", headers={"access-control-request-headers": "dpop"})
    assert preflight.status_code == 204 and preflight.headers["access-control-allow-headers"] == "dpop"


def test_static_files_are_served_before_the_app(server):
    assert server.get("/dashboard/").text == "<p>dashboard</p>"
    assert server.get("/dashboard/app.js").text == "ok()"
    redirected = server.get("/dashboard", follow_redirects=False)
    assert redirected.status_code == 307 and redirected.headers["location"] == "/dashboard/"
    assert server.get("/").json() == {"status": "ok"}  # "/" stays the app's


def test_static_paths_stay_inside_public(tmp_path):
    public = tmp_path / "public"
    public.mkdir()
    (tmp_path / "secret.txt").write_text("no")
    (public / "ok.txt").write_text("yes")
    assert _static("/ok.txt", public) is not None
    for path in ("/../secret.txt", "/ok.txt/../../secret.txt", "/", "/%2e%2e/secret.txt", "/a\x00"):
        assert _static(path, public) is None


def test_signup_and_writes_through_the_server(server):
    agent, account = signup(server, "srv-writer")
    created = create_post(server, agent, account["did"], "hello")
    record = server.get("/xrpc/com.atproto.repo.getRecord", params={
        "repo": account["did"], "collection": "app.bsky.feed.post", "rkey": created["uri"].rsplit("/", 1)[1]})
    assert record.json()["value"]["text"] == "hello"
    assert server.get(FIREHOSE).status_code == 426


# The firehose

def test_firehose_backfills_from_a_cursor_then_streams_live(server):
    agent, account = signup(server, "srv-firehose")
    with server.websocket_connect(f"{FIREHOSE}?cursor=0") as ws:
        assert [frame(ws.receive_bytes())[0]["t"] for _ in range(2)] == ["#identity", "#account"]
        create_post(server, agent, account["did"], "live")
        header, body = frame(ws.receive_bytes())
        assert header == {"op": 1, "t": "#commit"} and body["repo"] == account["did"] and body["seq"] == 3


def test_firehose_without_a_cursor_starts_at_the_head(server):
    agent, account = signup(server, "srv-head")
    with server.websocket_connect(FIREHOSE) as ws:
        create_post(server, agent, account["did"], "first live event")
        header, body = frame(ws.receive_bytes())
        assert header["t"] == "#commit" and body["seq"] == 3


def test_firehose_cursor_errors(server):
    signup(server, "srv-cursor")
    with pytest.raises(WebSocketDenialResponse) as denied:
        with server.websocket_connect(f"{FIREHOSE}?cursor=nope"):
            pass
    assert denied.value.status_code == 400 and denied.value.text == "Invalid cursor"
    with server.websocket_connect(f"{FIREHOSE}?cursor=99") as ws:
        header, body = frame(ws.receive_bytes())
        assert header == {"op": -1} and body["error"] == "FutureCursor"


# SQL

@pytest.mark.parametrize("sqlite,postgres", [
    ("SELECT a FROM t WHERE b = ? AND c > ?", "SELECT a FROM t WHERE b = %s AND c > %s"),
    ("SELECT '50%?' AS x WHERE y LIKE ?", "SELECT '50%%?' AS x WHERE y LIKE %s"),
    ("CREATE TABLE IF NOT EXISTS e (seq INTEGER PRIMARY KEY AUTOINCREMENT, p BLOB NOT NULL, n INTEGER, "
     "t TEXT DEFAULT (datetime('now')))",
     'CREATE TABLE IF NOT EXISTS e (seq BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY, p BYTEA NOT NULL, '
     "n BIGINT, t TEXT COLLATE \"C\" DEFAULT (to_char(now() AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI:SS')))"),
    ("SELECT CAST(x AS TEXT) FROM t", "SELECT CAST(x AS TEXT) FROM t"),
    ("SELECT 1 FROM g WHERE EXISTS (SELECT 1 FROM json_each(g.tags) WHERE value = ?)",
     "SELECT 1 FROM g WHERE EXISTS (SELECT 1 FROM json_array_elements_text((g.tags)::json) AS value WHERE value = %s)"),
    ("PRAGMA table_info(invites)",
     "SELECT column_name AS name FROM information_schema.columns WHERE table_schema = current_schema() "
     "AND table_name = 'invites'"),
])
def test_sqlite_statements_translate_to_postgres(sqlite, postgres):
    assert to_postgres(sqlite) == postgres


@pytest.mark.parametrize("bad", ["", "x", "../etc", 'a"; DROP SCHEMA public; --', "A" * 32, "0" * 31])
def test_account_ids_are_checked_before_naming_storage(bad):
    with pytest.raises(ValueError):
        check_account_id(bad)
    assert check_account_id("0" * 32) and check_account_id("f" * 64)


# Outbound fetch

@pytest.mark.parametrize("url", ["http://127.0.0.1:9/", "http://localhost:9/", "http://[::1]:9/",
                                 "http://169.254.169.254/latest/meta-data/", "http://10.0.0.1/"])
async def test_outbound_fetch_refuses_private_addresses(url):
    http = ServerHttp()
    try:
        with pytest.raises(ConnectionError, match="non-public"):
            await asyncio.wait_for(http.fetch(url, timeout=2), 5)
    finally:
        await http.close()


# Blobs

def check_blob_store(store, page: int):
    assert store.get("did:plc:a/missing") is None
    keys = [f"did:plc:a/bafy{n:04d}" for n in range(page + 1)]
    for key in keys:
        store.put(key, b"bytes-" + key.encode(), "image/png")
    store.put("did:plc:b/other", b"x", "text/plain")
    assert store.get(keys[0]) == (b"bytes-" + keys[0].encode(), "image/png")
    first, cursor = store.list("did:plc:a/", None)
    assert len(first) == page and cursor
    rest, end = store.list("did:plc:a/", cursor)
    assert first + rest == keys and end is None
    store.delete(keys)
    assert store.list("did:plc:a/", None) == ([], None) and store.get("did:plc:b/other") == (b"x", "text/plain")


def test_directory_blobs(tmp_path, monkeypatch):
    monkeypatch.setattr("roost_server.blobs.LIST_PAGE", 3)
    store = DirectoryBlobs(str(tmp_path / "blobs"))
    check_blob_store(store, 3)
    for bad in ("", "/abs", "did:plc:a/../../x"):
        with pytest.raises(ValueError):
            store.put(bad, b"", "text/plain")


def test_s3_blobs(monkeypatch):
    from moto import mock_aws

    monkeypatch.setattr("roost_server.blobs.LIST_PAGE", 3)
    with mock_aws():
        store = S3Blobs("roost-blobs", None, "us-east-1", "key", "secret")
        store._client.create_bucket(Bucket="roost-blobs")
        check_blob_store(store, 3)


@pytest.mark.skipif(not os.environ.get("ROOST_TEST_DATABASE_URL"), reason="needs ROOST_TEST_DATABASE_URL")
def test_postgres_blobs(monkeypatch):
    import psycopg

    monkeypatch.setattr("roost_server.blobs.LIST_PAGE", 3)
    admin_url = os.environ["ROOST_TEST_DATABASE_URL"]
    name = f"roost_blobs_t{os.getpid()}"
    with psycopg.connect(admin_url, autocommit=True) as connection:
        connection.execute(f'DROP DATABASE IF EXISTS "{name}"')
        connection.execute(f'CREATE DATABASE "{name}"')
    store = PostgresBlobs(urlunsplit(urlsplit(admin_url)._replace(path=f"/{name}")))
    try:
        check_blob_store(store, 3)
        store.put("did:plc:a/50%_x", b"x", "text/plain")
        assert store.list("did:plc:a/50%", None) == (["did:plc:a/50%_x"], None)
        assert store.list("did:plc:a/5_", None) == ([], None)
    finally:
        store.close()
        with psycopg.connect(admin_url, autocommit=True) as connection:
            connection.execute(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)')


# Concurrency (any backend: ROOST_TEST_BACKEND picks the storage behind `env`)

async def test_concurrent_writes_to_one_repo_serialize_into_one_commit_chain(env, enroll):
    rook = await enroll()
    results = await asyncio.gather(*(rook.create("app.bsky.feed.post", {"text": f"n{n}"}) for n in range(8)))
    assert all(result.status == 200 for result in results)
    commits = [frame(bytes(row["payload"]))[1] for row in env.sequencer.rows() if row["event_type"] == "commit"]
    assert [body["seq"] for body in commits] == sorted(body["seq"] for body in commits)
    assert all(later["since"] == earlier["rev"] for earlier, later in zip(commits, commits[1:]))
    listed = await rook.get("/xrpc/com.atproto.repo.listRecords",
                            params={"repo": rook.did, "collection": "app.bsky.feed.post", "limit": "50"})
    assert len(listed.json()["records"]) == 8
