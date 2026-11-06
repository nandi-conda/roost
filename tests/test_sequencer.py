# SPDX-License-Identifier: MIT
# Copyright (c) 2026 sol pbc

"""The firehose sequencer: monotonic seq, event frames, cursors, backfill, broadcast."""

import pytest

from fakes import SequencerDO
from roost import cbor
from roost.cbor import CID
from roost.sequencer import BACKFILL_LIMIT, Sequencer


def cid_of(value) -> str:
    return str(CID.for_cbor(cbor.encode(value)))


@pytest.fixture
def sequencer_do():
    return SequencerDO()


def event_types(sequencer_do) -> list[str]:
    return [row["event_type"] for row in sequencer_do.rows()]


def test_assigns_monotonic_seq_numbers(sequencer_do):
    sequencer = sequencer_do.sequencer
    assert sequencer.sequence_identity(did="did:plc:one", handle="one.rookery.test")["seq"] == 1
    assert sequencer.sequence_identity(did="did:plc:two", handle="two.rookery.test")["seq"] == 2


def test_sequence_commit_stores_a_commit_event(sequencer_do):
    sequencer = sequencer_do.sequencer
    sequencer.sequence_identity(did="did:plc:x", handle="x.rookery.test")
    result = sequencer.sequence_commit(
        did="did:plc:x", commit=cid_of({"type": "commit"}), rev="rev-1", since=None,
        prev_data=cid_of({"data": "prev"}), blocks=b"",
        ops=[{"action": "create", "path": "app.bsky.feed.post/test", "cid": cid_of({"record": 1}), "prev": None}],
    )
    assert result["seq"] == 2
    assert event_types(sequencer_do) == ["identity", "commit"]


def test_sequence_account_stores_an_account_event(sequencer_do):
    assert sequencer_do.sequencer.sequence_account(did="did:plc:x", active=True, status=None) == {"seq": 1}
    assert event_types(sequencer_do) == ["account"]


def account_bodies(sequencer_do) -> list[dict]:
    bodies = []
    for row in sequencer_do.rows():
        payload = bytes(row["payload"])
        _, pos = cbor.decode_first(payload)
        bodies.append(cbor.decode(payload[pos:]))
    return bodies


def test_account_event_omits_a_null_status(sequencer_do):
    sequencer_do.sequencer.sequence_account(did="did:plc:x", active=True, status=None)
    sequencer_do.sequencer.sequence_account(did="did:plc:x", active=False, status="deactivated")
    bodies = account_bodies(sequencer_do)
    assert "status" not in bodies[0] and bodies[1]["status"] == "deactivated"


def test_startup_drops_null_status_from_stored_account_events(sequencer_do):
    """#account frames written before the fix carried status: null; the lexicon has no null."""
    frame = cbor.encode({"op": 1, "t": "#account"}) + cbor.encode(
        {"did": "did:plc:x", "active": True, "status": None, "time": "2026-10-20T00:00:00.000Z", "seq": 1}
    )
    sequencer_do.sql.exec("DELETE FROM sequencer_migrations")
    sequencer_do.sql.exec("INSERT INTO firehose_events (did, event_type, payload) VALUES (?, 'account', ?)", "did:plc:x", frame)
    Sequencer(sequencer_do.sql, lambda: []).init_schema()
    assert account_bodies(sequencer_do) == [{"did": "did:plc:x", "active": True, "time": "2026-10-20T00:00:00.000Z", "seq": 1}]


async def test_signup_emits_identity_then_account(env, enroll):
    await enroll()
    assert event_types(env.sequencer) == ["identity", "account"]


async def test_creating_a_record_emits_a_commit(env, enroll):
    rook = await enroll()
    await rook.create("app.bsky.feed.post", {"text": "hello"}, "test-rkey")
    assert event_types(env.sequencer) == ["identity", "account", "commit"]


@pytest.mark.parametrize("raw,expected", [(None, None), ("0", 0), ("42", 42), (" 7 ", 7), ("12abc", 12), ("+3", 3)])
def test_cursor_parsing_follows_parse_int(sequencer_do, raw, expected):
    assert sequencer_do.sequencer.parse_cursor(raw) == expected


@pytest.mark.parametrize("raw", ["not-a-number", "", "-1", "abc12"])
def test_rejects_invalid_cursors(sequencer_do, raw):
    with pytest.raises(ValueError, match="Invalid cursor"):
        sequencer_do.sequencer.parse_cursor(raw)


async def test_subscribe_repos_upgrade_and_cursor_errors(client):
    path = "/xrpc/com.atproto.sync.subscribeRepos"
    assert (await client.get(path)).status == 426
    invalid = await client.get(path, params={"cursor": "not-a-number"}, headers={"upgrade": "websocket"})
    assert invalid.status == 400 and invalid.text == "Invalid cursor"
    upgraded = await client.get(path, headers={"upgrade": "websocket"})
    assert upgraded.status == 101 and upgraded.raw is not None


def test_backfills_only_events_after_the_cursor(sequencer_do):
    for n in range(3):
        sequencer_do.sequencer.sequence_identity(did=f"did:plc:{n}", handle=f"{n}.rookery.test")
    socket = sequencer_do.connect(2)
    assert len(socket.frames) == 1
    assert socket.events()[0][1]["did"] == "did:plc:2"
    assert socket.attachment == {"cursor": 3}


def test_backfill_is_bounded(sequencer_do):
    for n in range(BACKFILL_LIMIT + 5):
        sequencer_do.sequencer.sequence_account(did=f"did:plc:{n}", active=True, status=None)
    assert len(sequencer_do.connect(0).frames) == BACKFILL_LIMIT


def test_a_future_cursor_gets_an_error_frame_and_close(sequencer_do):
    sequencer_do.sequencer.sequence_identity(did="did:plc:x", handle="x.rookery.test")
    socket = sequencer_do.connect(99)
    header, body = socket.events()[0]
    assert header == {"op": -1} and body["error"] == "FutureCursor"
    assert socket.closed == (1008, "FutureCursor")


def test_live_events_reach_open_sockets_and_skip_closed_ones(sequencer_do):
    live, gone = sequencer_do.connect(), sequencer_do.connect()
    gone.close(1000, "bye")
    sequencer_do.sequencer.sequence_identity(did="did:plc:x", handle="x.rookery.test")
    assert len(live.frames) == 1 and live.attachment == {"cursor": 1}
    assert gone.frames == []
