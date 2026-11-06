# SPDX-License-Identifier: MIT
# Copyright (c) 2026 sol pbc

"""Move accounts from one roost host to another with their DIDs unchanged:
export each from FROM, import it into TO, then have TO re-point the DID's PLC
document (PDS endpoint and handle) at itself and ask the relays to crawl it.

    FROM=https://old.example TO=https://new.example uv run python scripts/migrate_host.py [did ...]

With no DIDs it moves every repo FROM lists. When TO already serves FROM's
hostname (a cutover: TO is reached at another URL until DNS moves), DIDs
already name the right PDS, so PLC and the relays are left alone. Both hosts must accept the same
operator token: ROOKERY_OPERATOR_TOKEN, or else the file
`pixi run cf-operator-token` saved. Re-running is safe: an account TO already has is only re-synced.
"""

import os
import sys
from urllib.parse import urlsplit

import httpx

from operator_token import TOKEN_FILE

RELAYS = ["https://bsky.network"]


def ok(response: httpx.Response, what: str) -> httpx.Response:
    if not response.is_success:
        raise SystemExit(f"{what}: {response.status_code} {response.text}")
    return response


def operator_token() -> str:
    token = os.environ.get("ROOKERY_OPERATOR_TOKEN")
    if token:
        return token
    if TOKEN_FILE.exists():
        return TOKEN_FILE.read_text().strip()
    raise SystemExit(f"Set ROOKERY_OPERATOR_TOKEN or run `pixi run cf-operator-token` to create {TOKEN_FILE}")


def list_dids(http: httpx.Client, source: str) -> list[str]:
    dids, cursor = [], None
    while True:
        params = {"limit": "500", **({"cursor": cursor} if cursor else {})}
        page = ok(http.get(f"{source}/xrpc/com.atproto.sync.listRepos", params=params), "listRepos").json()
        dids += [repo["did"] for repo in page["repos"]]
        cursor = page.get("cursor")
        if not cursor:
            return dids


def main() -> None:
    source, target = os.environ.get("FROM"), os.environ.get("TO")
    if not source or not target:
        print("FROM and TO are required", file=sys.stderr)
        raise SystemExit(2)
    token = operator_token()
    source, target = source.rstrip("/"), target.rstrip("/")
    auth = {"authorization": f"Bearer {token}"}

    with httpx.Client(timeout=120) as http:
        server_did = lambda host: ok(http.get(f"{host}/xrpc/com.atproto.server.describeServer"), "describeServer").json()["did"]
        same_host = server_did(source) == server_did(target)
        dids = sys.argv[1:] or list_dids(http, source)
        print(f"moving {len(dids)} account(s) from {source} to {target}")
        for did in dids:
            exported = ok(http.get(f"{source}/operator/account/export", params={"did": did}, headers=auth), f"export {did}")
            imported = http.post(f"{target}/operator/account/import", content=exported.content,
                                 headers={**auth, "content-type": "application/cbor"})
            if imported.status_code == 409:
                described = ok(http.get(f"{target}/xrpc/com.atproto.repo.describeRepo", params={"repo": did}),
                               f"describeRepo {did}")
                handle = described.json()["handle"]
                print(f"{did}: already on {target}")
            else:
                result = ok(imported, f"import {did}").json()
                handle = result["handle"]
                print(f"{did}: imported {handle} (rev {result['rev']}, {result['blocks']} blocks, {result['blobs']} blobs, "
                      f"{result['agents']} agents, {result['procs']} procs)")
            if same_host:
                continue
            synced = ok(http.post(f"{target}/operator/identity/sync", json={"did": did, "handle": handle}, headers=auth),
                        f"identity sync {did}").json()
            print(f"{did}: PLC now names {synced['pds']} as the PDS of {synced['handle']}")

        if same_host:
            print(f"{target} serves {source}'s hostname: PLC and relays unchanged; move DNS next")
            return
        hostname = urlsplit(target).hostname
        for relay in RELAYS:
            ok(http.post(f"{relay}/xrpc/com.atproto.sync.requestCrawl", json={"hostname": hostname}), f"requestCrawl {relay}")
            print(f"asked {relay} to crawl {hostname}")


if __name__ == "__main__":
    main()
