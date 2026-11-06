# SPDX-License-Identifier: MIT
# Copyright (c) 2026 sol pbc

"""The test Env on the FastAPI server's real storage instead of the
Cloudflare fakes: ROOST_TEST_BACKEND=sqlite (in-memory SQLite) or
ROOST_TEST_BACKEND=postgres with ROOST_TEST_DATABASE_URL (a server where a
fresh database is created per Env). Outbound HTTP and PLC stay faked; the
hooks tests reach into (sequencer rows, account storage, blob objects) are
read from the real storage."""

import itertools
import os
from urllib.parse import urlsplit, urlunsplit

from fakes import DEFAULT_VARS, Http, Plc, Socket
from roost import cbor
from roost.spaces.store import SpaceStore
from roost.web import Response
from roost_server.blobs import AsyncBlobs
from roost_server.platform import Env as PlatformEnv
from roost_server.platform import Firehose
from roost_server.sql import PostgresBackend, SqliteBackend

BACKEND = os.environ.get("ROOST_TEST_BACKEND", "fakes")
_open: list = []
_databases = itertools.count()


class MemoryBlobs:
    """The synchronous blob store shape, in a dict; pages of 2 to exercise cursors."""

    def __init__(self):
        self.objects: dict[str, tuple[bytes, str]] = {}

    def get(self, key):
        return self.objects.get(key)

    def put(self, key, data, content_type):
        self.objects[key] = (bytes(data), content_type)

    def list(self, prefix, cursor, page_size: int = 2):
        keys = sorted(key for key in self.objects if key.startswith(prefix) and (cursor is None or key > cursor))
        page = keys[:page_size]
        return page, (page[-1] if len(keys) > page_size else None)

    def delete(self, keys):
        for key in keys:
            self.objects.pop(key, None)


class TestBlobs(AsyncBlobs):
    def __init__(self, store: MemoryBlobs):
        super().__init__(store)
        self.objects = store.objects


def _postgres_backend():
    import psycopg

    admin_url = os.environ["ROOST_TEST_DATABASE_URL"]
    name = f"roost_t{os.getpid()}_{next(_databases)}"
    with psycopg.connect(admin_url, autocommit=True) as connection:
        connection.execute(f'DROP DATABASE IF EXISTS "{name}"')
        connection.execute(f'CREATE DATABASE "{name}"')
    parts = urlsplit(admin_url)
    backend = PostgresBackend(urlunsplit(parts._replace(path=f"/{name}")), max_connections=4)

    def drop():
        backend.close()
        with psycopg.connect(admin_url, autocommit=True) as connection:
            connection.execute(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)')
    return backend, drop


def _backend():
    if BACKEND == "sqlite":
        backend = SqliteBackend(":memory:")
        return backend, backend.close
    if BACKEND == "postgres":
        return _postgres_backend()
    raise ValueError(f"Unknown ROOST_TEST_BACKEND {BACKEND!r}")


class EventLog:
    """env.sequencer as the tests use it: rows(), connect()."""

    def __init__(self, backend):
        self._backend = backend

    def rows(self) -> list[dict]:
        with self._backend.sequencer_session() as sql:
            return sql.exec("SELECT seq, did, event_type, payload FROM firehose_events ORDER BY seq ASC")

    def latest(self) -> int:
        rows = self.rows()
        return rows[-1]["seq"] if rows else 0

    def connect(self, cursor: int | None = None) -> "LogSocket":
        return LogSocket(self, self.latest() if cursor is None else cursor)


class LogSocket(Socket):
    """A subscriber that sees every stored event after its cursor."""

    def __init__(self, log: EventLog, cursor: int):
        super().__init__()
        self._log = log
        self._cursor = cursor

    @property
    def frames(self):
        return [bytes(row["payload"]) for row in self._log.rows() if row["seq"] > self._cursor]

    @frames.setter
    def frames(self, value):
        pass


class _Sql:
    def __init__(self, backend, do_id):
        self._backend = backend
        self._do_id = do_id

    def exec(self, query, *params):
        with self._backend.account_session(self._do_id) as (sql, _):
            return sql.exec(query, *params)


class _AccountView:
    """env.account_do(id).account: RPC methods, plus .spaces on the account's storage."""

    def __init__(self, env, do_id):
        self._client = env.account(do_id)
        self.spaces = SpaceStore(_Sql(env.backend, do_id))

    def __getattr__(self, name):
        return getattr(self._client, name)


class ServerTestEnv(PlatformEnv):
    def __init__(self, **overrides):
        backend, self._drop = _backend()
        _open.append(self)
        store = MemoryBlobs()
        firehose = Firehose(backend)
        firehose.init_schema()
        super().__init__(dict(DEFAULT_VARS, **overrides), backend, store, Http(), firehose)
        self.backend = backend
        self.blobs = TestBlobs(store)
        self.plc = Plc()
        self.http.routes[self.ROOKERY_PLC_URL] = self.plc
        self.sequencer = EventLog(backend)
        self.accounts: list[str] = []
        self.background: list = []

    def new_account_id(self) -> str:
        do_id = super().new_account_id()
        self.accounts.append(do_id)
        return do_id

    def account_do(self, do_id: str):
        view = type("AccountDO", (), {})()
        view.account = _AccountView(self, do_id)
        return view

    async def subscribe_repos(self, request):
        if (request.header("upgrade") or "").lower() != "websocket":
            return Response(426, b"Expected WebSocket upgrade")
        try:
            cursor = self.firehose.parse_cursor(request.query("cursor"))
        except ValueError:
            return Response(400, b"Invalid cursor")
        return Response(101, b"", raw=self.sequencer.connect(cursor))

    def wait_until(self, coroutine) -> None:
        self.background.append(coroutine)

    def close(self) -> None:
        self._drop()


def close_all() -> None:
    while _open:
        _open.pop().close()
