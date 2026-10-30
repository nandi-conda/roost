# SPDX-License-Identifier: MIT
# Copyright (c) 2026 sol pbc

"""Write notifications: a writer's PDS tells the space host its repo advanced
(notifyWrite), and the space host sequences that and fans it out to registered
syncing services. A space governed here is handled in-process; a remote host is
called with service auth, and retryable failures wait in the writer's DO until
its next space write (or for a day).

Deletion notices (notifySpaceDeleted) are owed to every syncer registered when a
space is deleted: they wait in the authority's DO, retried on its later space
activity, until delivered, refused outright, or the registration expires."""

import json
import logging
import random
import time
from datetime import datetime

from ..encoding import s32_decode
from ..errors import XrpcError
from ..lexjson import lex_to_json
from .identity import local_account, service_endpoint
from .policy import authorize_user
from .refs import SpaceRef, space_host_aud

log = logging.getLogger("roost.spaces")

NOTIFY_WRITE = "com.atproto.space.notifyWrite"
NOTIFY_SPACE_DELETED = "com.atproto.space.notifySpaceDeleted"
MINUTE_MS, HOUR_MS, DAY_MS = 60_000, 3_600_000, 86_400_000


class RetryableError(Exception):
    pass


def next_retry_at(attempts: int) -> int:
    delay = min(MINUTE_MS * 2 ** min(attempts - 1, 6), HOUR_MS)
    return int(time.time() * 1000 + delay * (0.5 + random.random() / 2))


async def post_xrpc(env, account, service: str, lxm: str, body: dict) -> None:
    """POST to `service`'s endpoint with service auth signed by `account` (an AccountClient)."""
    endpoint = await service_endpoint(env, service)
    if not endpoint:
        raise RetryableError(f"could not resolve {service}")
    token = await account.sign_service_auth(aud=service, lxm=lxm, exp=int(time.time()) + 60)
    try:
        response = await env.http.fetch(
            f"{endpoint}/xrpc/{lxm}", method="POST", timeout=10,
            headers={"Authorization": f"Bearer {token['token']}", "Content-Type": "application/json"},
            body=json.dumps(lex_to_json(body), separators=(",", ":")),
        )
    except Exception as exc:
        raise RetryableError(str(exc)) from exc
    if response.status in (408, 425, 429) or response.status >= 500:
        raise RetryableError(f"{lxm} to {service} failed ({response.status})")
    if not response.ok:
        raise XrpcError("UpstreamFailure", f"{lxm} to {service} failed ({response.status}): {response.text()[:200]}")


async def process_notify_write(env, space: str, repo: str, repo_rev: str, digest: bytes) -> None:
    """Handle a write notification for a space governed by an account on this host."""
    ref = SpaceRef.parse(space)
    host = await local_account(env, ref.did)
    if not host:
        raise XrpcError("SpaceNotFound", "Space not found")
    try:
        rev_us = s32_decode(repo_rev[:11])
    except (ValueError, KeyError) as exc:
        raise XrpcError("InvalidRequest", "Invalid repoRev") from exc
    if rev_us > (time.time() * 1000 + 5 * MINUTE_MS) * 1000:
        raise XrpcError("FutureRev", "Repo revision is in the future")
    authority = env.account(host["do_id"])
    status = await authority.space_status(space=space)
    if not status["policy"] or status["deleted"]:
        raise XrpcError("SpaceNotFound", "Space not found")
    if not await authorize_user(env, authority, space, status["policy"], repo, "write"):
        raise XrpcError("Forbidden", "notifyWrite writer is not authorized", 403)
    env.wait_until(retry_deletion_notices(env, authority))
    sequence = await authority.space_record_writer(space=space, did=repo, repo_rev=repo_rev, hash=digest)
    if not sequence:
        return
    recipients = await authority.space_recipients(space=space)
    if not recipients:
        return

    async def fan_out():
        body = {"space": space, "repo": repo, "repoRev": repo_rev, "data": digest, **sequence}
        for recipient in recipients:
            try:
                await post_xrpc(env, authority, recipient["service_did"], NOTIFY_WRITE, body)
            except Exception as exc:
                log.warning("notify %s of %s failed: %s", recipient["service_did"], space, exc)
    env.wait_until(fan_out())


async def _deliver(env, writer, writer_did: str, space: str, repo_rev: str, digest: bytes) -> None:
    ref = SpaceRef.parse(space)
    if await local_account(env, ref.did):
        await process_notify_write(env, space, writer_did, repo_rev, digest)
        return
    body = {"space": space, "repo": writer_did, "repoRev": repo_rev, "data": digest}
    await post_xrpc(env, writer, space_host_aud(ref.did), NOTIFY_WRITE, body)


async def notify_write(env, writer, writer_did: str, space: str, commit: dict | None) -> None:
    """After a space commit: deliver now, queue a retryable failure, then drain older queued ones."""
    if commit:
        try:
            await _deliver(env, writer, writer_did, space, commit["rev"], commit["data"])
            await writer.space_clear_notification(space=space, repo_rev=commit["rev"])
        except RetryableError as exc:
            log.warning("notifyWrite for %s queued for retry: %s", space, exc)
            await writer.space_queue_notification(
                space=space, repo_rev=commit["rev"], hash=commit["data"], attempts=1,
                retry_at=next_retry_at(1), expires_at=int(time.time() * 1000) + DAY_MS,
            )
        except XrpcError as exc:
            log.warning("notifyWrite for %s will not be retried: %s", space, exc.message)
    env.wait_until(retry_pending(env, writer, writer_did))


async def retry_pending(env, writer, writer_did: str) -> None:
    await retry_deletion_notices(env, writer)
    for retry in await writer.space_due_notifications():
        try:
            await _deliver(env, writer, writer_did, retry["space"], retry["repo_rev"], bytes(retry["hash"]))
            await writer.space_clear_notification(space=retry["space"], repo_rev=retry["repo_rev"])
        except RetryableError:
            attempts = retry["attempts"] + 1
            await writer.space_queue_notification(
                space=retry["space"], repo_rev=retry["repo_rev"], hash=bytes(retry["hash"]), attempts=attempts,
                retry_at=min(next_retry_at(attempts), retry["expires_at"]), expires_at=retry["expires_at"],
            )
        except Exception as exc:
            log.warning("notifyWrite retry for %s dropped: %s", retry["space"], exc)
            await writer.space_clear_notification(space=retry["space"], repo_rev=retry["repo_rev"])


def _iso_ms(value: str) -> int:
    return int(datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp() * 1000)


async def _deliver_deletion(env, authority, space: str, service: str, attempts: int, expires_at: int) -> None:
    try:
        await post_xrpc(env, authority, service, NOTIFY_SPACE_DELETED, {"space": space})
    except RetryableError as exc:
        log.warning("notifySpaceDeleted to %s for %s will be retried: %s", service, space, exc)
        await authority.space_queue_deletion_notice(
            space=space, service_did=service, attempts=attempts + 1,
            retry_at=min(next_retry_at(attempts + 1), expires_at), expires_at=expires_at,
        )
        return
    except Exception as exc:
        log.warning("notifySpaceDeleted to %s for %s refused: %s", service, space, exc)
    await authority.space_clear_deletion_notice(space=space, service_did=service)


async def notify_space_deleted(env, authority, space: str, recipients: list[dict]) -> None:
    """Persist a notice for each registered syncer, then try delivering them now."""
    now_ms = int(time.time() * 1000)
    pending = [(recipient["service_did"], _iso_ms(recipient["expires_at"])) for recipient in recipients]
    for service, expires_at in pending:
        await authority.space_queue_deletion_notice(
            space=space, service_did=service, attempts=0, retry_at=now_ms, expires_at=expires_at,
        )

    async def run():
        for service, expires_at in pending:
            await _deliver_deletion(env, authority, space, service, 0, expires_at)
    env.wait_until(run())


async def retry_deletion_notices(env, authority) -> None:
    for notice in await authority.space_due_deletion_notices():
        await _deliver_deletion(env, authority, notice["space"], notice["service_did"], notice["attempts"],
                                notice["expires_at"])
