# Running on Cloudflare Workers

`wrangler.cloudflare.jsonc` deploys roost as the Python Worker `rookery-pds` on the
custom domain `roost.latha.org`, with handles under `.roost.latha.org`.
`rookery.latha.org`, the old hostname, is still routed to the same Worker.
Durable Objects hold each account's repo, D1 (`rookery-directory`) the account
directory, R2 (`rookery-blobs`) blobs; wrangler creates the database and bucket
by name on the first deploy. The firehose Durable Object uses WebSocket
hibernation, so a relay holding `subscribeRepos` open costs nothing while idle.

The first deploy is done by an operator from a local checkout (`pixi run` installs Node and uv; `pywrangler` vendors the Python dependencies and proxies to wrangler):

```sh
pixi run cf-login      # once
pixi run cf-deploy
pixi run cf-secrets    # once: OAUTH_NONCE_SECRET
```

After the first deploy, `just deploy` (or `pixi run deploy`) does the routine
release in one step: `git pull --ff-only`, `pixi run cf-deploy`, then
`pixi run sync-identities`, which skips DIDs already on the host and asks the
relays to crawl it.

Every push to main also deploys itself: `.github/workflows/deploy.yml` runs the
tests, then `pixi run cf-deploy`. It reads the `CLOUDFLARE_API_TOKEN` secret (an
org or repo Actions secret): a token from the **Edit Cloudflare Workers**
template plus **Account · D1 · Edit**, scoped to the nandi account and the
latha.org zone. CI does not run `sync-identities`, since that needs the
operator token, so after a deploy that moves DIDs run it locally (or use
`just deploy`, which does both).

Handles resolve over HTTPS. The zone has an advanced certificate for
`*.roost.latha.org`, a proxied wildcard DNS record `*.roost.latha.org` (AAAA
`100::`) points every handle host at Cloudflare, and the Worker route
`*.roost.latha.org/.well-known/atproto-did` answers with the DID the directory
holds for that host. So a new signup's handle verifies as soon as it exists,
with no per-account DNS record.

Accounts from before that also have a TXT record `_atproto.<handle>` =
`"did=<did>"`. The Worker writes one on signup and on every handle change
only when it holds a Cloudflare API token with **Zone · DNS · Edit** on
`latha.org` (`CLOUDFLARE_ZONE_ID` is already a var); prod runs without it:

```sh
pixi run cf-dns-token        # paste the token; pixi run cf-drop-dns-token removes it
```

## Operator routes

`/operator/*` take `Authorization: Bearer <token>` and exist only when
`ROOKERY_OPERATOR_TOKEN_SHA256` (the token's hex SHA-256, a secret) is set.
`pixi run cf-operator-token` makes a new token, saves it to
`~/.config/roost/operator-token` and installs its hash, replacing any old one.
The scripts below read the token from that file when `ROOKERY_OPERATOR_TOKEN`
is unset.

- `GET /operator/account/export?did=` returns an account as CBOR: repo blocks,
  signing and rotation keys, blobs.
- `POST /operator/account/import` recreates an export in a new Durable Object,
  with its directory row and agentbus index.
- `POST /operator/identity/sync {did, handle}` signs a PLC operation with the
  account's rotation key that points the DID at this host.

## Moving accounts between hosts

```sh
FROM=https://old.host TO=https://roost.latha.org pixi run migrate-host
```

exports every repo FROM lists, imports it into TO, syncs its PLC identity to TO
and asks bsky.network to crawl TO. DIDs, keys and handles stay the same, and
re-running skips accounts TO already has.

## Changing the hostname

`ROOKERY_HOSTNAME` is the origin the PDS puts in DID documents, OAuth metadata
and invite links. To move to a new one, route both hostnames to the Worker,
set `ROOKERY_HOSTNAME` to the new one and list the old one in
`ROOKERY_LEGACY_HOSTNAMES`: requests that reach the old hostname are still
checked against it (DPoP `htu`, WelcomeMat `aud`), so enrolled agents keep
working until they switch. Then point each DID at the new host:

```sh
pixi run sync-identities
```

It re-signs each DID's PLC document with the new host and handle (skipping DIDs
already there), then asks the relays to crawl the new host.

## Changing the handle domain

Set `ROOKERY_HANDLE_DOMAIN` to the new suffix and list the old one in
`ROOKERY_LEGACY_HANDLE_DOMAINS`: an old handle then still finds its account
(sign-in, `resolveHandle`, `repo=` parameters) under the same name. After
deploying, move every account over:

```sh
pixi run rename-handles
```

It re-signs each DID's PLC document with `<name><new domain>`, emits an
`#identity` event, writes the TXT record (with the DNS token set), checks each
new handle resolves over DNS, and asks the relays to crawl. The old handles'
TXT records can stay; they no longer verify on Bluesky, since the DID now names
the new handle.
