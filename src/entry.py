# SPDX-License-Identifier: MIT
# Copyright (c) 2026 sol pbc

"""Cloudflare Python Worker entry: the Worker, the Account and Sequencer
Durable Objects, and adapters from the runtime's bindings to what the
roost package expects (see roost/app.py)."""

import asyncio

import js
from pyodide.ffi import to_js
from workers import DurableObject, Response, WorkerEntrypoint
from workers import fetch as runtime_fetch

from roost import rpc
from roost.account import Account
from roost.app import ENV_VARS, handle
from roost.net import HttpResponse
from roost.sequencer import Sequencer
from roost.web import Headers, Request

SEQUENCER_NAME = "sequencer"


def _bytes(value) -> bytes:
    """Bytes from whatever the runtime handed back (memoryview, JS buffer, bytes)."""
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value)
    if hasattr(value, "to_bytes"):
        return value.to_bytes()
    return bytes(js.Uint8Array.new(value).to_py())


def _plain(value):
    if isinstance(value, memoryview):
        return bytes(value)
    if isinstance(value, dict):
        return {key: _plain(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_plain(item) for item in value]
    return value


def _js_bytes(data: bytes):
    return to_js(data)


# Bindings

class SqlStorage:
    """DO SQLite: exec(query, *params) -> list[dict]."""

    def __init__(self, sql):
        self._sql = sql

    def exec(self, query: str, *params) -> list[dict]:
        params = [_js_bytes(param) if isinstance(param, (bytes, bytearray)) else param for param in params]
        return [_plain(dict(row)) for row in self._sql.exec(query, *params).toArray()]


class D1:
    def __init__(self, db):
        self._db = db

    def _statement(self, sql: str, params):
        statement = self._db.prepare(sql)
        return statement.bind(*params) if params else statement

    async def first(self, sql: str, *params) -> dict | None:
        row = await self._statement(sql, params).first()
        return _plain(dict(row)) if row is not None else None

    async def all(self, sql: str, *params) -> list[dict]:
        result = await self._statement(sql, params).all()
        return [_plain(dict(row)) for row in result["results"]]

    async def run(self, sql: str, *params) -> int:
        result = await self._statement(sql, params).run()
        return int(result["meta"]["changes"])

    async def batch(self, statements: list[tuple[str, list]]) -> None:
        await self._db.batch([self._statement(sql, params) for sql, params in statements])


class Blobs:
    """R2: get -> (bytes, content_type) | None, put, list(prefix, cursor) -> (keys, cursor), delete."""

    def __init__(self, bucket):
        self._bucket = bucket

    async def get(self, key: str):
        found = await self._bucket.get(key)
        if found is None:
            return None
        data = _bytes(await found.arrayBuffer())
        metadata = found.httpMetadata or {}
        content_type = metadata.get("contentType") if isinstance(metadata, dict) else getattr(metadata, "contentType", None)
        return data, content_type

    async def put(self, key: str, data: bytes, content_type: str) -> None:
        await self._bucket.put(key, _js_bytes(data), {"httpMetadata": {"contentType": content_type}})

    async def list(self, prefix: str, cursor: str | None):
        options = {"prefix": prefix}
        if cursor:
            options["cursor"] = cursor
        listed = await self._bucket.list(options)
        keys = [item["key"] if isinstance(item, dict) else item.key for item in listed["objects"]]
        if listed["truncated"]:
            if not listed.get("cursor"):
                raise RuntimeError("R2 blob listing was truncated without a cursor")
            return keys, listed["cursor"]
        return keys, None

    async def delete(self, keys: list[str]) -> None:
        await self._bucket.delete(keys)


class Http:
    async def fetch(self, url: str, method: str = "GET", headers: dict | None = None, body: str | bytes | None = None,
                    redirect: str = "follow", timeout: float | None = None) -> HttpResponse:
        options = {"method": method, "redirect": redirect}
        if headers:
            options["headers"] = headers
        if body is not None:
            options["body"] = body

        async def go():
            response = await runtime_fetch(url, **options)
            return HttpResponse(
                status=response.status,
                body=await response.bytes(),
                headers={key.lower(): value for key, value in response.headers.items()},
            )
        return await asyncio.wait_for(go(), timeout) if timeout else await go()


async def _call_do(stub, request: str) -> str:
    return await stub.rpc(request)


class Env:
    """What roost.app sees: configuration attributes plus platform services."""

    def __init__(self, env, wait_until):
        for name in ENV_VARS:
            value = getattr(env, name, None)
            setattr(self, name, value if isinstance(value, str) and value != "" else None)
        self._env = env
        self.db = D1(env.DIRECTORY)
        self.blobs = Blobs(env.BLOBS)
        self.http = Http()
        self.wait_until = wait_until

    def new_account_id(self) -> str:
        return self._env.ACCOUNT.newUniqueId().toString()

    def account(self, do_id: str) -> rpc.AccountClient:
        stub = self._env.ACCOUNT.get(self._env.ACCOUNT.idFromString(do_id))
        return rpc.AccountClient(lambda request: _call_do(stub, request))

    async def subscribe_repos(self, request):
        from roost.web import Response as AppResponse
        stub = self._env.SEQUENCER.getByName(SEQUENCER_NAME)
        return AppResponse(raw=await stub.fetch(request.raw))


# Worker

def _to_runtime(response) -> Response:
    if response.raw is not None:
        return response.raw
    headers = {}
    for key, value in response.headers:
        headers[key] = value
    body = response.body if response.body and response.status not in (101, 204, 205, 304) else None
    return Response(body, status=response.status, headers=headers)


class Default(WorkerEntrypoint):
    async def fetch(self, request):
        raw = request.js_object if hasattr(request, "js_object") else request
        headers = Headers((str(pair[0]), str(pair[1])) for pair in raw.headers.entries())

        async def read_body():
            return _bytes(await raw.arrayBuffer())

        app_request = Request(str(raw.method), str(raw.url), headers, body_reader=read_body, raw=raw)
        env = Env(self.env, self.ctx.waitUntil)
        return _to_runtime(await handle(app_request, env))


# Durable Objects

class SequencerClient:
    """The Account DO's view of the Sequencer DO."""

    def __init__(self, env):
        self._stub = env.SEQUENCER.getByName(SEQUENCER_NAME)

    async def _call(self, method: str, **args):
        return rpc.unwrap(await self._stub.rpc(rpc.request(method, args)))

    async def sequence_commit(self, **args):
        return await self._call("sequence_commit", **args)

    async def sequence_identity(self, **args):
        return await self._call("sequence_identity", **args)

    async def sequence_account(self, **args):
        return await self._call("sequence_account", **args)


class AccountDurableObject(DurableObject):
    def __init__(self, ctx, env):
        super().__init__(ctx, env)
        self.account = Account(SqlStorage(ctx.storage.sql), SequencerClient(env), Blobs(env.BLOBS))
        self.account.init_schema()

    async def rpc(self, request: str) -> str:
        return await rpc.serve(self.account, rpc.ACCOUNT_METHODS, request)


class _Socket:
    def __init__(self, ws):
        self._ws = ws

    def send(self, frame: bytes) -> None:
        self._ws.send(_js_bytes(frame))

    def close(self, code: int, reason: str) -> None:
        self._ws.close(code, reason)

    def get_attachment(self) -> dict | None:
        attachment = self._ws.deserializeAttachment()
        if attachment is None or not hasattr(attachment, "to_py"):
            return attachment
        return attachment.to_py()

    def set_attachment(self, value: dict) -> None:
        self._ws.serializeAttachment(to_js(value, dict_converter=js.Object.fromEntries))


class _AsyncSequencer:
    """Sequencer methods as coroutines, for rpc.serve."""

    def __init__(self, sequencer: Sequencer):
        self._sequencer = sequencer

    async def sequence_commit(self, **args):
        return self._sequencer.sequence_commit(**args)

    async def sequence_identity(self, **args):
        return self._sequencer.sequence_identity(**args)

    async def sequence_account(self, **args):
        return self._sequencer.sequence_account(**args)


SEQUENCER_METHODS = frozenset({"sequence_commit", "sequence_identity", "sequence_account"})


class SequencerDurableObject(DurableObject):
    def __init__(self, ctx, env):
        super().__init__(ctx, env)
        self.sequencer = Sequencer(
            SqlStorage(ctx.storage.sql), lambda: [_Socket(ws) for ws in ctx.getWebSockets()],
        )
        self.sequencer.init_schema()

    async def rpc(self, request: str) -> str:
        return await rpc.serve(_AsyncSequencer(self.sequencer), SEQUENCER_METHODS, request)

    async def fetch(self, request):
        raw = request.js_object if hasattr(request, "js_object") else request
        upgrade = raw.headers.get("Upgrade")
        if not upgrade or str(upgrade).lower() != "websocket":
            return Response("Expected WebSocket upgrade", status=426)
        # A missing param is JS null, which Pyodide hands over as jsnull, not None.
        raw_cursor = js.URL.new(raw.url).searchParams.get("cursor")
        try:
            cursor = self.sequencer.parse_cursor(raw_cursor if isinstance(raw_cursor, str) else None)
        except ValueError:
            return Response("Invalid cursor", status=400)
        pair = js.WebSocketPair.new()
        client, server = pair.object_values()
        self.ctx.acceptWebSocket(server)
        socket = _Socket(server)
        socket.set_attachment({"cursor": cursor or 0})
        if cursor is not None:
            self.sequencer.backfill(socket, cursor)
        return Response(None, status=101, web_socket=client)

    async def webSocketMessage(self, ws, message):
        pass

    async def webSocketClose(self, ws, code, reason, was_clean):
        pass


__all__ = ["AccountDurableObject", "Default", "SequencerDurableObject"]
