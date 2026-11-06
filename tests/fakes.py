# SPDX-License-Identifier: MIT
# Copyright (c) 2026 sol pbc

"""In-process stand-ins for the Cloudflare platform: D1 and DO SQLite on
sqlite3, R2 as a dict, Durable Objects as objects behind the same string RPC
boundary the Worker uses, and outbound HTTP routed to handlers."""

import asyncio
import json
import os
import sqlite3
import uuid
from urllib.parse import parse_qsl, urlsplit

from roost import rpc
from roost.account import Account
from roost.app import ENV_VARS, handle
from roost.cbor import CID
from roost import cbor
from roost.net import HttpResponse
from roost.sequencer import Sequencer
from roost.web import Headers, Request


def _connect() -> sqlite3.Connection:
    connection = sqlite3.connect(":memory:", isolation_level=None)
    connection.row_factory = sqlite3.Row
    return connection


class Sql:
    """DO SQLite: exec(query, *params) -> list[dict]."""

    def __init__(self):
        self.connection = _connect()

    def exec(self, query: str, *params) -> list[dict]:
        return [dict(row) for row in self.connection.execute(query, params).fetchall()]


class D1:
    def __init__(self):
        self.connection = _connect()

    async def first(self, sql: str, *params):
        row = self.connection.execute(sql, params).fetchone()
        return dict(row) if row else None

    async def all(self, sql: str, *params):
        return [dict(row) for row in self.connection.execute(sql, params).fetchall()]

    async def run(self, sql: str, *params) -> int:
        return self.connection.execute(sql, params).rowcount

    async def batch(self, statements) -> None:
        self.connection.execute("BEGIN")
        try:
            for sql, params in statements:
                self.connection.execute(sql, params)
        except Exception:
            self.connection.execute("ROLLBACK")
            raise
        self.connection.execute("COMMIT")


class Blobs:
    def __init__(self):
        self.objects: dict[str, tuple[bytes, str]] = {}

    async def get(self, key):
        return self.objects.get(key)

    async def put(self, key, data, content_type):
        self.objects[key] = (bytes(data), content_type)

    async def list(self, prefix, cursor, page_size: int = 2):
        # Opaque cursor: the last key handed out, so deletes between pages are safe.
        keys = sorted(key for key in self.objects if key.startswith(prefix) and (cursor is None or key > cursor))
        page = keys[:page_size]
        return page, (page[-1] if len(keys) > page_size else None)

    async def delete(self, keys):
        for key in keys:
            self.objects.pop(key, None)


class Socket:
    """A firehose client: collects frames, closes like a WebSocket."""

    def __init__(self):
        self.frames: list[bytes] = []
        self.closed: tuple[int, str] | None = None
        self.attachment = None

    def send(self, frame):
        if self.closed:
            raise RuntimeError("socket closed")
        self.frames.append(bytes(frame))

    def close(self, code, reason):
        self.closed = (code, reason)

    def get_attachment(self):
        return self.attachment

    def set_attachment(self, value):
        self.attachment = json.loads(json.dumps(value))

    def events(self) -> list[tuple[dict, dict]]:
        out = []
        for frame in self.frames:
            header, end = cbor.decode_first(frame)
            out.append((header, cbor.decode_first(frame, end)[0]))
        return out


class SequencerDO:
    def __init__(self):
        self.sql = Sql()
        self.sockets: list[Socket] = []
        self.sequencer = Sequencer(self.sql, lambda: [s for s in self.sockets if not s.closed])
        self.sequencer.init_schema()

    def connect(self, cursor: int | None = None) -> Socket:
        socket = Socket()
        socket.set_attachment({"cursor": cursor or 0})
        self.sockets.append(socket)
        if cursor is not None:
            self.sequencer.backfill(socket, cursor)
        return socket

    def rows(self) -> list[dict]:
        return self.sql.exec("SELECT seq, did, event_type, payload FROM firehose_events ORDER BY seq ASC")


class SequencerClient:
    def __init__(self, sequencer_do: SequencerDO):
        self._do = sequencer_do

    async def _call(self, method, args):
        # Round-trip through the RPC encoding, as the DOs do.
        return rpc.decode(rpc.encode(getattr(self._do.sequencer, method)(**rpc.decode(rpc.encode(args)))))

    async def sequence_commit(self, **args):
        return await self._call("sequence_commit", args)

    async def sequence_identity(self, **args):
        return await self._call("sequence_identity", args)

    async def sequence_account(self, **args):
        return await self._call("sequence_account", args)


class AccountDO:
    def __init__(self, sequencer_do: SequencerDO, blobs: Blobs):
        self.sql = Sql()
        self.account = Account(self.sql, SequencerClient(sequencer_do), blobs)
        self.account.init_schema()
        self.lock = asyncio.Lock()

    async def rpc(self, request: str) -> str:
        async with self.lock:  # DOs run one request at a time
            return await rpc.serve(self.account, rpc.ACCOUNT_METHODS, request)


class Http:
    """Outbound fetch: `routes` maps a URL prefix to handler(method, url, headers, body) -> HttpResponse."""

    def __init__(self):
        self.routes: dict[str, object] = {}
        self.calls: list[dict] = []

    async def fetch(self, url, method="GET", headers=None, body=None, redirect="follow", timeout=None):
        call = {"url": url, "method": method, "headers": dict(headers or {}), "body": body, "redirect": redirect}
        self.calls.append(call)
        for prefix in sorted(self.routes, key=len, reverse=True):
            if url.startswith(prefix):
                result = self.routes[prefix](method, url, call["headers"], body)
                if asyncio.iscoroutine(result):
                    result = await result
                return result
        raise ConnectionError(f"no route for {url}")


class Plc:
    """The PLC directory: accepts operations, serves the audit log and DID documents."""

    def __init__(self):
        self.log: dict[str, list[dict]] = {}
        self.reject: int | None = None

    def __call__(self, method, url, headers, body):
        path = urlsplit(url).path.strip("/").split("/")
        if method == "POST":
            if self.reject:
                return HttpResponse(self.reject, b'{"message":"rejected"}')
            op = json.loads(body)
            cid = str(CID.for_cbor(cbor.encode(op)))
            self.log.setdefault(path[0], []).append({"did": path[0], "cid": cid, "nullified": False, "operation": op})
            return HttpResponse(200, b"")
        if len(path) == 3 and path[1:] == ["log", "audit"] and path[0] in self.log:
            return HttpResponse(200, json.dumps(self.log[path[0]]).encode())
        if len(path) == 1 and path[0] in self.log:
            return HttpResponse(200, json.dumps(self.did_doc(path[0])).encode())
        return HttpResponse(404, b'{"message":"DID not registered"}')

    def publish(self, did: str, op: dict) -> None:
        self.log.setdefault(did, []).append({"did": did, "cid": "", "nullified": False, "operation": op})

    def did_doc(self, did: str) -> dict:
        op = self.log[did][-1]["operation"]
        return {
            "id": did,
            "alsoKnownAs": op.get("alsoKnownAs", []),
            "verificationMethod": [
                {"id": f"{did}#{name}", "type": "Multikey", "controller": did,
                 "publicKeyMultibase": key.removeprefix("did:key:")}
                for name, key in op.get("verificationMethods", {}).items()
            ],
            "service": [
                {"id": f"#{name}", "type": service["type"], "serviceEndpoint": service["endpoint"]}
                for name, service in op.get("services", {}).items()
            ],
        }


DEFAULT_VARS = {
    "ROOKERY_HOSTNAME": "rookery.test",
    "ROOKERY_HANDLE_DOMAIN": ".rookery.test",
    "ROOKERY_PLC_URL": "https://plc.directory",
    "OAUTH_NONCE_SECRET": "test-oauth-nonce-secret",
    # sha256("test-operator-token")
    "ROOKERY_OPERATOR_TOKEN_SHA256": "21a41ec35ffe053418f5ebab652c9b4cb07a643a9100640d18b635e0df503928",
}
VAR_NAMES = ENV_VARS


class Env:
    def __init__(self, **overrides):
        values = dict(DEFAULT_VARS, **overrides)
        for name in VAR_NAMES:
            setattr(self, name, values.get(name))
        self.db = D1()
        self.blobs = Blobs()
        self.http = Http()
        self.plc = Plc()
        self.http.routes[self.ROOKERY_PLC_URL] = self.plc
        self.sequencer = SequencerDO()
        self.accounts: dict[str, AccountDO] = {}
        self.background: list = []

    def new_account_id(self) -> str:
        do_id = uuid.uuid4().hex * 2
        self.accounts[do_id] = AccountDO(self.sequencer, self.blobs)
        return do_id

    def account(self, do_id: str) -> rpc.AccountClient:
        target = self.accounts.get(do_id)
        if target is None:
            raise ValueError(f"Invalid Durable Object ID: {do_id}")
        return rpc.AccountClient(target.rpc)

    def account_do(self, do_id: str) -> AccountDO:
        return self.accounts[do_id]

    async def subscribe_repos(self, request):
        from roost.web import Response
        if (request.header("upgrade") or "").lower() != "websocket":
            return Response(426, b"Expected WebSocket upgrade")
        try:
            cursor = self.sequencer.sequencer.parse_cursor(request.query("cursor"))
        except ValueError:
            return Response(400, b"Invalid cursor")
        socket = self.sequencer.connect(cursor)
        return Response(101, b"", raw=socket)

    def wait_until(self, coroutine) -> None:
        self.background.append(coroutine)


class TestResponse:
    def __init__(self, response):
        self.status = response.status
        self.body = response.body
        self.raw = response.raw
        self.headers = {key.lower(): value for key, value in response.headers}

    def json(self):
        return json.loads(self.body)

    @property
    def text(self) -> str:
        return self.body.decode()


class Client:
    """Requests straight into the app, as the Worker would hand them over."""

    def __init__(self, env: Env, origin: str = "https://rookery.test"):
        self.env = env
        self.origin = origin

    async def request(self, method: str, path: str, *, json_body=None, body: bytes | str | None = None,
                      headers: dict | None = None, params: dict | None = None, form: dict | None = None) -> TestResponse:
        headers = dict(headers or {})
        if json_body is not None:
            body = json.dumps(json_body)
            headers.setdefault("content-type", "application/json")
        if form is not None:
            from urllib.parse import urlencode
            body = urlencode(form)
            headers.setdefault("content-type", "application/x-www-form-urlencoded")
        if isinstance(body, str):
            body = body.encode()
        url = path if path.startswith("http") else self.origin + path
        if params:
            from urllib.parse import urlencode
            url += ("&" if "?" in url else "?") + urlencode(params)
        request = Request(method, url, Headers(headers.items()), body=body or b"")
        response = TestResponse(await handle(request, self.env))
        while self.env.background:
            await self.env.background.pop(0)
        return response

    async def get(self, path, **kwargs):
        return await self.request("GET", path, **kwargs)

    async def post(self, path, **kwargs):
        return await self.request("POST", path, **kwargs)

    async def put(self, path, **kwargs):
        return await self.request("PUT", path, **kwargs)

    async def delete(self, path, **kwargs):
        return await self.request("DELETE", path, **kwargs)


def query_of(url: str) -> dict:
    return dict(parse_qsl(urlsplit(url).query))


if os.environ.get("ROOST_TEST_BACKEND", "fakes") != "fakes":
    # The same suite on the FastAPI server's storage (see server_env.py).
    from server_env import ServerTestEnv as Env  # noqa: E402,F811
