# SPDX-License-Identifier: MIT
# Copyright (c) 2026 sol pbc

"""The firehose: the logic behind the Sequencer Durable Object.

Every event gets the next seq in the DO's SQLite and is stored as its finished
frame (CBOR header + CBOR body), so backfill replays bytes and live sockets get
the same bytes. Sockets are hibernatable; each carries its cursor as its
attachment.
"""

from datetime import datetime, timezone

from . import cbor
from .cbor import CID

SCHEMA = """CREATE TABLE IF NOT EXISTS firehose_events (
  seq INTEGER PRIMARY KEY AUTOINCREMENT,
  did TEXT NOT NULL,
  event_type TEXT NOT NULL,
  payload BLOB NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
)"""

MIGRATIONS_SCHEMA = "CREATE TABLE IF NOT EXISTS sequencer_migrations (name TEXT PRIMARY KEY)"
DROP_NULL_STATUS = "account-drop-null-status"

BACKFILL_LIMIT = 1000
TOO_BIG_BYTES = 1_000_000


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def error_frame(error: str, message: str) -> bytes:
    return cbor.encode({"op": -1}) + cbor.encode({"error": error, "message": message})


class Sequencer:
    """`sql.exec(q, *p) -> list[dict]`; `sockets()` returns the accepted
    websockets, each with send(bytes), close(code, reason), and
    get_attachment()/set_attachment(dict)."""

    def __init__(self, sql, sockets):
        self.sql = sql
        self.sockets = sockets

    def init_schema(self) -> None:
        """Create or migrate the event log; once per storage, before any call."""
        self.sql.exec(SCHEMA)
        self.sql.exec(MIGRATIONS_SCHEMA)
        if not self.sql.exec("SELECT 1 AS x FROM sequencer_migrations WHERE name = ?", DROP_NULL_STATUS):
            self._drop_null_account_status()
            self.sql.exec("INSERT INTO sequencer_migrations (name) VALUES (?)", DROP_NULL_STATUS)

    def _drop_null_account_status(self) -> None:
        """#account frames once carried status: null; the lexicon only allows a known string or no field."""
        for row in self.sql.exec("SELECT seq, payload FROM firehose_events WHERE event_type = 'account'"):
            payload = bytes(row["payload"])
            header, pos = cbor.decode_first(payload)
            body = cbor.decode(payload[pos:])
            if "status" in body and body["status"] is None:
                del body["status"]
                self.sql.exec(
                    "UPDATE firehose_events SET payload = ? WHERE seq = ?", cbor.encode(header) + cbor.encode(body), row["seq"],
                )

    def _append(self, did: str, event_type: str, t: str, body: dict) -> int:
        seq = self.sql.exec(
            "INSERT INTO firehose_events (did, event_type, payload) VALUES (?, ?, ?) RETURNING seq",
            did, event_type, b"\x00",
        )[0]["seq"]
        frame = cbor.encode({"op": 1, "t": t}) + cbor.encode(dict(body, seq=seq))
        self.sql.exec("UPDATE firehose_events SET payload = ? WHERE seq = ?", frame, seq)
        self._broadcast(frame, seq)
        return seq

    def sequence_commit(self, did, commit, rev, since, prev_data, blocks: bytes, ops) -> dict:
        repo_ops = []
        for op in ops:
            entry = {
                "action": op["action"],
                "path": op["path"],
                "cid": CID.parse(op["cid"]) if op["cid"] else None,
            }
            if op.get("prev"):
                entry["prev"] = CID.parse(op["prev"])
            repo_ops.append(entry)
        seq = self._append(did, "commit", "#commit", {
            "repo": did,
            "commit": CID.parse(commit),
            "rev": rev,
            "since": since,
            "blocks": bytes(blocks),
            "ops": repo_ops,
            "prevData": CID.parse(prev_data) if prev_data else None,
            "rebase": False,
            "tooBig": len(blocks) > TOO_BIG_BYTES,
            "blobs": [],
            "time": now_iso(),
        })
        return {"seq": seq}

    def sequence_identity(self, did: str, handle: str) -> dict:
        return {"seq": self._append(did, "identity", "#identity", {"did": did, "handle": handle, "time": now_iso()})}

    def sequence_account(self, did: str, active: bool, status: str | None) -> dict:
        body = {"did": did, "active": active, "time": now_iso()}
        if status is not None:
            body["status"] = status
        return {"seq": self._append(did, "account", "#account", body)}

    def latest_seq(self) -> int:
        rows = self.sql.exec("SELECT MAX(seq) AS seq FROM firehose_events")
        return (rows[0]["seq"] if rows else None) or 0

    def parse_cursor(self, raw: str | None) -> int | None:
        """None for no cursor; raises ValueError for one that isn't a non-negative integer."""
        if raw is None:
            return None
        digits = raw.strip()
        sign = digits[:1] in "+-" and digits[:1] or ""
        body = digits[len(sign):]
        prefix = ""
        for ch in body:
            if not ch.isdigit():
                break
            prefix += ch
        if not prefix:
            raise ValueError("Invalid cursor")
        value = int(sign + prefix)
        if value < 0:
            raise ValueError("Invalid cursor")
        return value

    def events_after(self, cursor: int, limit: int) -> list[dict]:
        """Stored frames with seq > cursor, oldest first: [{seq, payload}]."""
        return self.sql.exec(
            "SELECT seq, payload FROM firehose_events WHERE seq > ? ORDER BY seq ASC LIMIT ?", cursor, limit,
        )

    def backfill(self, ws, cursor: int) -> None:
        latest = self.latest_seq()
        if cursor > latest and latest > 0:
            ws.send(error_frame("FutureCursor", "Cursor is in the future"))
            ws.close(1008, "FutureCursor")
            return
        rows = self.events_after(cursor, BACKFILL_LIMIT)
        last = cursor
        for row in rows:
            last = row["seq"]
            ws.send(bytes(row["payload"]))
        if last > cursor:
            attachment = ws.get_attachment() or {}
            attachment["cursor"] = last
            ws.set_attachment(attachment)

    def _broadcast(self, frame: bytes, seq: int) -> None:
        for ws in self.sockets():
            try:
                ws.send(frame)
                attachment = ws.get_attachment() or {}
                attachment["cursor"] = seq
                ws.set_attachment(attachment)
            except Exception:  # a closing socket must not fail the commit
                pass
