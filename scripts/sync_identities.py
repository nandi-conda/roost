# SPDX-License-Identifier: MIT
# Copyright (c) 2026 sol pbc

"""Point every DID on a roost host at that host after a hostname change: for
each repo HOST lists, re-sign its PLC document (PDS endpoint, handle and the
#atproto_kem key spaces need) with the account's rotation key, then ask the
relays to crawl HOST.

    uv run python scripts/sync_identities.py [did ...]

HOST defaults to https://roost.latha.org. The operator token comes from
ROOKERY_OPERATOR_TOKEN, or else the file `pixi run cf-operator-token` saved.
With no DIDs it syncs every repo HOST lists. DIDs whose PLC document already
names HOST and publishes an #atproto_kem key, and whose handle's _atproto TXT
names them, are skipped, so re-running is safe. (Syncing also rewrites the TXT
when HOST has CLOUDFLARE_DNS_TOKEN.)
"""

import os
import sys
from urllib.parse import urlsplit

import httpx

from migrate_host import RELAYS, list_dids, ok, operator_token

PLC = "https://plc.directory"
DOH = "https://cloudflare-dns.com/dns-query"


def txt_names(http: httpx.Client, handle: str, did: str) -> bool:
    answer = ok(http.get(DOH, params={"name": f"_atproto.{handle}", "type": "TXT"},
                         headers={"accept": "application/dns-json"}), f"DNS {handle}").json().get("Answer") or []
    return any(record.get("data", "").strip('"') == f"did={did}" for record in answer)


def main() -> None:
    host = os.environ.get("HOST", "https://roost.latha.org").rstrip("/")
    token = operator_token()
    auth = {"authorization": f"Bearer {token}"}

    with httpx.Client(timeout=120) as http:
        dids = sys.argv[1:] or list_dids(http, host)
        print(f"syncing {len(dids)} DID(s) to {host}")
        for did in dids:
            doc = ok(http.get(f"{PLC}/{did}/data"), f"PLC {did}").json()
            handle = ok(http.get(f"{host}/xrpc/com.atproto.repo.describeRepo", params={"repo": did}),
                        f"describeRepo {did}").json()["handle"]
            if doc["services"]["atproto_pds"]["endpoint"] == host and "atproto_kem" in doc["verificationMethods"] \
                    and txt_names(http, handle, did):
                print(f"{did}: already on {host} with a KEM key and a TXT record")
                continue
            synced = ok(http.post(f"{host}/operator/identity/sync", json={"did": did, "handle": handle},
                                  headers=auth), f"identity sync {did}").json()
            print(f"{did}: PLC now names {synced['pds']} as the PDS of {synced['handle']}, with a KEM key")

        hostname = urlsplit(host).hostname
        for relay in RELAYS:
            ok(http.post(f"{relay}/xrpc/com.atproto.sync.requestCrawl", json={"hostname": hostname}), f"requestCrawl {relay}")
            print(f"asked {relay} to crawl {hostname}")


if __name__ == "__main__":
    main()
