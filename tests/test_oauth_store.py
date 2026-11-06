# SPDX-License-Identifier: MIT
# Copyright (c) 2026 sol pbc

"""The OAuth D1 tables: round-trips, atomic consumes, guarded rotation, replay guards."""


import pytest

from conftest import unique
from roost.oauth import store
from roost.oauth.store import CODE_FIELDS, PAR_FIELDS, SESSION_FIELDS, TOKEN_FIELDS

NOW = 1_700_000_000


@pytest.fixture
async def db(env):
    await store.init_oauth(env.db)
    return env.db


def pick(row: dict | None, fields: tuple) -> dict | None:
    return {field: row[field] for field in fields} if row else None


def session_row(**overrides) -> dict:
    return dict({
        "session_id": unique("session"), "refresh_token_hash": unique("refresh"), "client_id": "https://client.example",
        "did": "did:plc:rotate", "scope": "atproto", "dpop_jkt": "jkt", "exp": NOW + 3600,
    }, **overrides)


def code_row(**overrides) -> dict:
    suffix = unique("code")
    return dict({
        "code_hash": f"code-hash-{suffix}", "client_id": f"https://client.example/{suffix}",
        "redirect_uri": f"https://client.example/cb/{suffix}", "code_challenge": f"challenge-{suffix}",
        "scope": "atproto", "did": f"did:plc:{suffix}", "dpop_jkt": f"jkt-{suffix}", "exp": NOW + 120,
    }, **overrides)


async def test_init_is_idempotent(db):
    await store.init_oauth(db)
    await store.init_oauth(db)


async def test_round_trips_every_table(db):
    suffix = unique("rt")
    par = {
        "request_uri": f"urn:ietf:params:oauth:request_uri:{suffix}", "client_id": f"https://client.example/{suffix}",
        "params": '{"response_type":"code"}', "code_challenge": f"challenge-{suffix}",
        "redirect_uri": f"https://client.example/cb/{suffix}", "scope": "atproto", "dpop_jkt": f"jkt-{suffix}", "exp": NOW + 60,
    }
    await store.insert_par_request(db, par, NOW)
    assert pick(await store.get_par_request(db, par["request_uri"]), PAR_FIELDS) == par

    code = code_row()
    await store.insert_code(db, code, NOW)
    assert pick(await db.first("SELECT * FROM oauth_codes WHERE code_hash = ?", code["code_hash"]), CODE_FIELDS) == code

    session = session_row()
    await store.insert_session(db, session, NOW)
    assert pick(await store.get_session_by_refresh_hash(db, session["refresh_token_hash"]), SESSION_FIELDS) == session

    token = dict({k: session[k] for k in ("session_id", "client_id", "did", "scope", "dpop_jkt")},
                 access_token_hash=unique("access"), exp=NOW + 300)
    await store.insert_token(db, token, NOW)
    assert pick(await store.get_token_by_hash(db, token["access_token_hash"]), TOKEN_FIELDS) == token

    assert await store.insert_dpop_jti(db, unique("jti"), NOW + 300, NOW) is True


async def test_rejects_duplicate_refresh_hashes(db):
    session = session_row()
    await store.insert_session(db, session, NOW)
    with pytest.raises(Exception, match="UNIQUE constraint failed"):
        await store.insert_session(db, dict(session, session_id=unique("session-b")), NOW)


async def test_detects_dpop_jti_replay(db):
    jti = unique("jti-replay")
    assert await store.insert_dpop_jti(db, jti, NOW + 300, NOW) is True
    assert await store.insert_dpop_jti(db, jti, NOW + 300, NOW) is False


async def test_consumes_codes_atomically(db):
    code = code_row()
    await store.insert_code(db, code, NOW)
    assert pick(await store.consume_code(db, code["code_hash"]), CODE_FIELDS) == code
    assert await db.first("SELECT 1 FROM oauth_codes WHERE code_hash = ?", code["code_hash"]) is None
    assert await store.consume_code(db, code["code_hash"]) is None


async def test_rotates_refresh_hashes_with_a_guarded_update(db):
    session = session_row()
    await store.insert_session(db, session, NOW)
    assert await store.rotate_session_refresh(db, session["session_id"], session["refresh_token_hash"], unique("new")) is True
    assert await store.rotate_session_refresh(db, session["session_id"], session["refresh_token_hash"], unique("never")) is False


async def test_reads_tokens_through_their_owning_session(db):
    session = session_row(scope="atproto repo:org.example.thing")
    await store.insert_session(db, session, NOW)
    token = dict({k: session[k] for k in ("session_id", "client_id", "did", "scope", "dpop_jkt")},
                 access_token_hash=unique("access-join"), exp=NOW + 300)
    await store.insert_token(db, token, NOW)
    joined = await store.get_token_with_session(db, token["access_token_hash"])
    assert pick(joined, TOKEN_FIELDS) == token and joined["session_exp"] == session["exp"]
    await db.run("DELETE FROM oauth_sessions WHERE session_id = ?", session["session_id"])
    assert await store.get_token_with_session(db, token["access_token_hash"]) is None
