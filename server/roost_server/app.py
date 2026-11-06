# SPDX-License-Identifier: MIT
# Copyright (c) 2026 sol pbc

"""The FastAPI app: every HTTP request goes to roost.app.handle, the same
function the Worker calls; static files under public/ are served first (as
Workers static assets are); the firehose is a websocket route.

Configuration is the Worker's variables (ROOKERY_HOSTNAME, ...) as
environment variables, plus storage:

  DATABASE_URL           Postgres (FastAPI Cloud's Neon/Supabase integration sets it)
  ROOST_DATA_DIR         or: a directory for SQLite files (self-hosting, local dev)
  S3_BUCKET, S3_ENDPOINT_URL, S3_REGION, S3_ACCESS_KEY_ID, S3_SECRET_ACCESS_KEY
                         blob bytes in S3 or R2 (R2: S3_ENDPOINT_URL=https://<account>.r2.cloudflarestorage.com)
  ROOST_BLOB_DIR         or: a directory for blob bytes (default ROOST_DATA_DIR/blobs)
  ROOST_ALLOW_PRIVATE_FETCH=1   let outbound fetches reach private addresses (local dev only)
"""

import asyncio
import os
from contextlib import asynccontextmanager
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

from fastapi import FastAPI, Request, WebSocket
from starlette.responses import FileResponse, PlainTextResponse, RedirectResponse
from starlette.responses import Response as StarletteResponse
from starlette.websockets import WebSocketDisconnect, WebSocketState

from roost.app import handle
from roost.sequencer import BACKFILL_LIMIT, error_frame
from roost.web import Headers
from roost.web import Request as RoostRequest

from .blobs import open_blobs
from .platform import Env, Firehose, Http
from .sql import open_backend

PUBLIC_DIR = Path(__file__).resolve().parents[2] / "public"
METHODS = ["GET", "HEAD", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"]
NO_BODY = (101, 204, 205, 304)


def build_env(environ: dict, *, backend=None, blob_store=None, http=None) -> Env:
    backend = backend or open_backend(environ.get("DATABASE_URL"), environ.get("ROOST_DATA_DIR"))
    blob_store = blob_store or open_blobs(environ)
    http = http or Http(allow_private=environ.get("ROOST_ALLOW_PRIVATE_FETCH") == "1")
    firehose = Firehose(backend)
    firehose.init_schema()
    env = Env(environ, backend, blob_store, http, firehose)
    env.backend = backend
    return env


def _static(path: str, public: Path):
    """A Workers-assets style answer for GET/HEAD, or None to fall through to the app."""
    if path == "/" or "\x00" in path:
        return None
    target = (public / path.lstrip("/")).resolve()
    if not target.is_relative_to(public) or target == public:
        return None
    if target.is_dir():
        if not (target / "index.html").is_file():
            return None
        if not path.endswith("/"):
            return RedirectResponse(path + "/", status_code=307)
        return FileResponse(target / "index.html")
    if target.is_file():
        return FileResponse(target)
    return None


def _request_url(request: Request) -> str:
    """The URL the client used: FastAPI Cloud (and most hosts) terminate TLS in front."""
    parts = urlsplit(str(request.url))
    scheme = request.headers.get("x-forwarded-proto", parts.scheme).split(",")[0].strip() or parts.scheme
    return urlunsplit((scheme, parts.netloc, parts.path, parts.query, ""))


def _headers(request: Request) -> Headers:
    joined: dict[str, str] = {}
    for key, value in request.headers.items():
        joined[key] = f"{joined[key]}, {value}" if key in joined else value
    return Headers(joined.items())


def create_app(environ: dict | None = None, *, env: Env | None = None, public_dir: Path = PUBLIC_DIR) -> FastAPI:
    environ = dict(os.environ) if environ is None else environ
    public = public_dir.resolve()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        app.state.env = env or build_env(environ)
        try:
            yield
        finally:
            await app.state.env.drain()
            if env is None:
                await app.state.env.http.close()
                app.state.env.backend.close()

    app = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)

    @app.websocket("/xrpc/com.atproto.sync.subscribeRepos")
    async def subscribe_repos(websocket: WebSocket):
        firehose: Firehose = websocket.app.state.env.firehose
        try:
            cursor = firehose.parse_cursor(websocket.query_params.get("cursor"))
        except ValueError:
            await websocket.send_denial_response(PlainTextResponse("Invalid cursor", 400))
            return
        latest = await firehose.latest_seq()
        await websocket.accept()
        if cursor is not None and cursor > latest > 0:
            await websocket.send_bytes(error_frame("FutureCursor", "Cursor is in the future"))
            await websocket.close(1008, "FutureCursor")
            return

        async def send(position: int):
            while True:
                rows = await firehose.events_after(position, BACKFILL_LIMIT)
                for row in rows:
                    await websocket.send_bytes(bytes(row["payload"]))
                    position = row["seq"]
                if len(rows) < BACKFILL_LIMIT:
                    await firehose.wait()

        async def receive():
            while (await websocket.receive())["type"] != "websocket.disconnect":
                pass

        tasks = [asyncio.ensure_future(send(latest if cursor is None else cursor)), asyncio.ensure_future(receive())]
        try:
            done, _ = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
            for task in done:
                failure = task.exception()
                # A send to a client that just left fails; that is a disconnect, not an error.
                if failure is not None and not isinstance(failure, WebSocketDisconnect) \
                        and websocket.client_state != WebSocketState.DISCONNECTED \
                        and websocket.application_state != WebSocketState.DISCONNECTED:
                    raise failure
        finally:
            for task in tasks:
                task.cancel()

    @app.api_route("/{path:path}", methods=METHODS)
    async def everything(request: Request):
        if request.method in ("GET", "HEAD"):
            static = _static(request.url.path, public)
            if static is not None:
                return static
        roost_request = RoostRequest(request.method, _request_url(request), _headers(request),
                                     body_reader=request.body)
        response = await handle(roost_request, request.app.state.env)
        out = StarletteResponse(b"" if response.status in NO_BODY else response.body, status_code=response.status)
        for key, value in response.headers:
            out.headers.append(key, value)
        return out

    return app
