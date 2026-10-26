# SPDX-License-Identifier: MIT
# Copyright (c) 2026 sol pbc

import inspect
import itertools
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from agent import Agent  # noqa: E402
from fakes import Client, Env  # noqa: E402
from roost import app as roost_app  # noqa: E402
from roost.oauth import client_metadata, permission_sets  # noqa: E402
from roost import access, directory  # noqa: E402
from roost.humans import store as human_store  # noqa: E402
from roost.mcp import store as mcp_store  # noqa: E402
from roost.spaces import auth as space_auth  # noqa: E402

ORIGIN = "https://rookery.test"
OPERATOR_TOKEN = "test-operator-token"
_names = itertools.count()


@pytest.hookimpl(tryfirst=True)
def pytest_pycollect_makeitem(collector, name, obj):
    # Mark async tests for anyio before parametrization sees them.
    if collector.funcnamefilter(name) and inspect.iscoroutinefunction(obj):
        pytest.mark.anyio(obj)


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture(autouse=True)
def _reset_module_state():
    client_metadata.reset_cache()
    access.reset_jwks_cache()
    directory._idempotency_ensured = False
    human_store._initialized = False
    mcp_store._initialized = False
    space_auth._revocations_ensured = False
    permission_sets._initialized = False
    roost_app._requested_crawl = False
    yield


@pytest.fixture
def env():
    return Env()


@pytest.fixture
def client(env):
    return Client(env)


def unique(prefix: str) -> str:
    return f"{prefix}{next(_names)}"


class Rook:
    """An enrolled agent and shortcuts for authenticated XRPC calls."""

    def __init__(self, client: Client, agent: Agent, did: str, handle: str):
        self.client = client
        self.agent = agent
        self.did = did
        self.handle = handle

    async def post(self, path: str, body=None, **kwargs):
        return await self.client.post(path, json_body=body, headers=dict(self.agent.auth_headers("POST", path), **kwargs.pop("headers", {})), **kwargs)

    async def get(self, path: str, **kwargs):
        return await self.client.get(path, headers=dict(self.agent.auth_headers("GET", path), **kwargs.pop("headers", {})), **kwargs)

    async def create(self, collection: str, record: dict, rkey: str | None = None):
        body = {"repo": self.did, "collection": collection, "record": record}
        if rkey:
            body["rkey"] = rkey
        return await self.post("/xrpc/com.atproto.repo.createRecord", body)

    def do(self):
        return self.client.env


async def tos_text(client: Client) -> str:
    return (await client.get("/tos")).text


async def signup(client: Client, name: str, agent: Agent | None = None, **extra):
    tos = await tos_text(client)
    agent = agent or Agent(ORIGIN, tos)
    agent.tos_text = tos
    agent.access_token = agent.make_access_token()
    response = await client.post(
        "/api/signup", json_body=agent.signup_body(name, **extra), headers={"DPoP": agent.dpop("POST", "/api/signup")},
    )
    return response, agent


@pytest.fixture
def enroll(client):
    async def enroll_rook(name: str | None = None, **extra) -> Rook:
        response, agent = await signup(client, name or unique("rook"), **extra)
        assert response.status == 200, response.text
        body = response.json()
        return Rook(client, agent, body["did"], body["handle"])
    return enroll_rook
