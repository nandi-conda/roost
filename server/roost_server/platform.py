# SPDX-License-Identifier: MIT
# Copyright (c) 2026 sol pbc

"""What roost.app sees outside Cloudflare: the same `env` shape src/entry.py
builds from Worker bindings (see roost/app.py), on a SQL backend (sql.py),
a blob store (blobs.py) and httpx.

Account calls cross the same string RPC boundary (roost.rpc) the Worker uses
to reach an Account Durable Object, and run on a worker thread inside one
transaction holding the account's lock, so the synchronous storage code in
roost.account / roost.storage runs unchanged.
"""

import asyncio
import ipaddress
import logging
import socket
import uuid

from roost import rpc
from roost.account import Account
from roost.app import ENV_VARS
from roost.net import HttpResponse
from roost.sequencer import Sequencer
from roost.web import Response

from .blobs import AsyncBlobs, InlineBlobs

log = logging.getLogger("roost.server")


class InlineSequencer:
    """The Account's view of the sequencer, on the same thread and transaction."""

    def __init__(self, sequencer: Sequencer):
        self._sequencer = sequencer
        self.sequenced = False

    async def sequence_commit(self, **args):
        self.sequenced = True
        return self._sequencer.sequence_commit(**args)

    async def sequence_identity(self, **args):
        self.sequenced = True
        return self._sequencer.sequence_identity(**args)

    async def sequence_account(self, **args):
        self.sequenced = True
        return self._sequencer.sequence_account(**args)


class Accounts:
    """Runs Account methods against a backend: the Durable Objects' replacement."""

    def __init__(self, backend, blob_store, on_sequenced):
        self._backend = backend
        self._blobs = InlineBlobs(blob_store)
        self._on_sequenced = on_sequenced
        self._ready: set[str] = set()

    def _run(self, do_id: str, request: str) -> tuple[str, bool]:
        with self._backend.account_session(do_id) as (sql, sequencer_sql):
            sequencer = InlineSequencer(Sequencer(sequencer_sql, lambda: []))
            account = Account(sql, sequencer, self._blobs)
            if do_id not in self._ready:
                account.init_schema()
            response = asyncio.run(rpc.serve(account, rpc.ACCOUNT_METHODS, request))
        self._ready.add(do_id)
        return response, sequencer.sequenced

    async def call(self, do_id: str, request: str) -> str:
        response, sequenced = await asyncio.to_thread(self._run, do_id, request)
        if sequenced:
            self._on_sequenced()
        return response

    def client(self, do_id: str) -> rpc.AccountClient:
        return rpc.AccountClient(lambda request: self.call(do_id, request))


# Outbound HTTP

def _public_address(address: str) -> bool:
    ip = ipaddress.ip_address(address)
    if ip.version == 6 and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return ip.is_global


class _GuardedBackend:
    """An httpcore network backend that connects only to public addresses, and
    to the address it checked (no second DNS lookup to rebind)."""

    def __init__(self, inner):
        self._inner = inner

    async def connect_tcp(self, host, port, timeout=None, local_address=None, socket_options=None):
        infos = await asyncio.get_running_loop().getaddrinfo(host, port, type=socket.SOCK_STREAM)
        addresses = [info[4][0] for info in infos]
        if not addresses or not all(_public_address(address) for address in addresses):
            raise ConnectionError(f"Refusing to connect to non-public address for {host}")
        return await self._inner.connect_tcp(addresses[0], port, timeout=timeout, local_address=local_address,
                                             socket_options=socket_options)

    async def connect_unix_socket(self, *args, **kwargs):
        raise ConnectionError("Unix sockets are not allowed")

    async def sleep(self, seconds):
        await self._inner.sleep(seconds)


class Http:
    """env.http: fetch() as the Worker runtime's fetch, on httpx. Outbound
    requests reach only public addresses (the Worker sandbox guarantees this on
    Cloudflare; client_id and DID URLs are caller-chosen) unless allow_private."""

    def __init__(self, allow_private: bool = False):
        import httpx

        transport = httpx.AsyncHTTPTransport(retries=0)
        if not allow_private:
            pool = transport._pool  # httpcore.AsyncConnectionPool
            pool._network_backend = _GuardedBackend(pool._network_backend)
        self._client = httpx.AsyncClient(transport=transport, timeout=30.0,
                                         headers={"user-agent": "roost-pds"})

    async def fetch(self, url: str, method: str = "GET", headers: dict | None = None, body: str | bytes | None = None,
                    redirect: str = "follow", timeout: float | None = None) -> HttpResponse:
        if isinstance(body, str):
            body = body.encode("utf-8")
        response = await self._client.request(
            method, url, headers=headers, content=body, follow_redirects=redirect == "follow",
            timeout=timeout if timeout else 30.0,
        )
        return HttpResponse(
            status=response.status_code,
            body=response.content,
            headers={key.lower(): value for key, value in response.headers.items()},
        )

    async def close(self) -> None:
        await self._client.aclose()


# The firehose

class Firehose:
    """Wakes subscribers when events may be waiting. Events written on this
    process wake them at once; events from other replicas are picked up by
    polling (POLL_S), since every replica reads the same event table."""

    POLL_S = 1.0

    def __init__(self, backend):
        self._backend = backend
        self._changed = asyncio.Event()

    def init_schema(self, seq_floor: int = 0) -> None:
        """seq_floor: start numbering above it. A host taking over another's
        hostname sets it past the old host's last seq, because relays resume
        from their cursor and a cursor ahead of us is a FutureCursor error."""
        with self._backend.sequencer_session() as sql:
            Sequencer(sql, lambda: []).init_schema()
        if seq_floor:
            self._backend.raise_seq_floor(seq_floor)

    def notify(self) -> None:
        self._changed.set()
        self._changed = asyncio.Event()

    async def wait(self) -> None:
        try:
            await asyncio.wait_for(self._changed.wait(), self.POLL_S)
        except TimeoutError:
            pass

    def _read(self, method: str, *args):
        with self._backend.sequencer_session() as sql:
            return getattr(Sequencer(sql, lambda: []), method)(*args)

    async def latest_seq(self) -> int:
        return await asyncio.to_thread(self._read, "latest_seq")

    async def events_after(self, cursor: int, limit: int) -> list[dict]:
        return await asyncio.to_thread(self._read, "events_after", cursor, limit)

    @staticmethod
    def parse_cursor(raw: str | None) -> int | None:
        return Sequencer(None, None).parse_cursor(raw)


class Env:
    """env for roost.app.handle: configuration attributes plus services."""

    def __init__(self, environ: dict, backend, blob_store, http, firehose: Firehose):
        for name in ENV_VARS:
            value = environ.get(name)
            setattr(self, name, value if isinstance(value, str) and value != "" else None)
        self.db = backend.directory
        self.blobs = AsyncBlobs(blob_store)
        self.http = http
        self.firehose = firehose
        self._accounts = Accounts(backend, blob_store, firehose.notify)
        self._tasks: set[asyncio.Task] = set()

    def new_account_id(self) -> str:
        return uuid.uuid4().hex

    def account(self, do_id: str) -> rpc.AccountClient:
        return self._accounts.client(do_id)

    async def subscribe_repos(self, request) -> Response:
        # Upgrades are served by the websocket route; a plain GET lands here, as on the Worker.
        return Response(426, b"Expected WebSocket upgrade")

    def wait_until(self, coroutine) -> None:
        task = asyncio.get_running_loop().create_task(coroutine)
        self._tasks.add(task)

        def done(finished: asyncio.Task):
            self._tasks.discard(finished)
            if not finished.cancelled() and finished.exception():
                log.error("background task failed: %r", finished.exception())
        task.add_done_callback(done)

    async def drain(self) -> None:
        while self._tasks:
            await asyncio.gather(*list(self._tasks), return_exceptions=True)
