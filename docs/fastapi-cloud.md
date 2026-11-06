# roost on FastAPI Cloud

`server/` runs the same `src/roost` package the Cloudflare Worker runs, as a
FastAPI app. Nothing in the Worker changed: pushes to main still deploy it, and
roost.latha.org stays on Cloudflare until the operator cuts over.

## what replaces what

| Worker (Cloudflare) | FastAPI app | why |
|---|---|---|
| D1 directory | Postgres, default schema (`DATABASE_URL`) | FastAPI Cloud's Neon / Supabase integrations set `DATABASE_URL` |
| Account Durable Object (its SQLite) | one Postgres schema per account, `account_<id>` | keeps the per-agent storage boundary; every account call is one transaction under a per-account advisory lock, so repo writes serialize as they do in a DO |
| Sequencer Durable Object | `roost_sequencer.firehose_events` | events commit in the same transaction as the repo write, under a global lock, so seq order is commit order |
| hibernating firehose websockets | `GET /xrpc/com.atproto.sync.subscribeRepos` websocket route | each socket reads the event table from its cursor; a write wakes local sockets at once, other replicas pick it up within 1 s |
| R2 | a Postgres table, `roost_blobs.blobs` (bytea), when `DATABASE_URL` is set; or any S3 bucket (`S3_*`, R2 works through its S3 API) | FastAPI Cloud has no disk; blobs are capped at 60 MB (`MAX_BLOB_BYTES`), far under bytea's 1 GB, but they count against the Neon plan's storage |
| Workers static assets (`public/`) | served before the app, same paths | `/dashboard/` keeps working |
| Worker `fetch` | httpx, refusing private and link-local addresses | the Worker sandbox did this for free; client_id and DID URLs are caller-chosen |

The SQL stays in SQLite's dialect (it still runs on D1 and DO SQLite). The
Postgres adapter in `server/roost_server/sql.py` rewrites the few SQLite-isms
roost uses (`?`, column types, `datetime('now')`, `json_each`, `PRAGMA
table_info`, `sqlite_master`) and words unique violations the way D1 does.
TEXT columns get `COLLATE "C"` so ordering (rkeys, cids, cursors) is bytewise,
as on SQLite.

Without `DATABASE_URL` the app uses SQLite files under `ROOST_DATA_DIR`
(one file per account), for local dev or a VPS with a disk.

## configuration

Same variables as `wrangler.cloudflare.jsonc` (`ROOKERY_HOSTNAME`,
`ROOKERY_HANDLE_DOMAIN`, `ROOKERY_LEGACY_HOSTNAMES`, `ROOKERY_LEGACY_HANDLE_DOMAINS`,
`ROOKERY_PLC_URL`, `ROOKERY_RELAY_HOSTS`, `CLOUDFLARE_ZONE_ID`) and secrets
(`OAUTH_NONCE_SECRET`, `ROOKERY_OPERATOR_TOKEN_SHA256`, optionally
`CLOUDFLARE_DNS_TOKEN`), as FastAPI Cloud environment variables. Plus:

| variable | value |
|---|---|
| `DATABASE_URL` | set by the Neon or Supabase integration |
| `S3_BUCKET` | `rookery-blobs` (to share the Worker's R2 bucket) |
| `S3_ENDPOINT_URL` | `https://2612967e82750619224e7446c4c41b0b.r2.cloudflarestorage.com` |
| `S3_ACCESS_KEY_ID`, `S3_SECRET_ACCESS_KEY` | an R2 API token with Object Read & Write on that bucket (secret) |
| `S3_REGION` | optional; R2 uses `auto` (the default) |

## deploy

CI on the fileapi forge (repo `nandi.uk/roost`, `.forge/jobs.toml`) runs
`ci/fastapi-deploy.sh` on every push to its main. The script bundles `server/`
with `src/roost` and `public/`, finds or creates the FastAPI Cloud app `roost`,
copies the forge secrets onto it, and runs `fastapi deploy`. Forge secrets:

| secret | kind |
|---|---|
| `FASTAPI_TOKEN` | FastAPI Cloud user token (required) |
| `DATABASE_URL` | Postgres URL, e.g. Neon's pooled connection string |
| `S3_BUCKET`, `S3_ENDPOINT_URL`, `S3_ACCESS_KEY_ID`, `S3_SECRET_ACCESS_KEY` | blob bucket |
| `OAUTH_NONCE_SECRET` | random hex; generated once and kept on the app if absent |
| `ROOKERY_OPERATOR_TOKEN_SHA256` | optional, enables operator routes |
| `ROOKERY_HOSTNAME`, `ROOKERY_HANDLE_DOMAIN` | optional; default `<app>.fastapicloud.dev` |

Without `DATABASE_URL` or `S3_BUCKET` the app runs on SQLite and files under
`/tmp/roost`: ephemeral, lost on every restart, redeploy or scale-to-zero, and
per replica. Fine for a first look, not for accounts anyone keeps.

GitHub pushes do not trigger it; the Cloudflare Worker deploy is separate.

Local run: `cd server && ROOST_DATA_DIR=/tmp/roost ROOKERY_HOSTNAME=localhost ROOKERY_PLC_URL=https://plc.directory
ROOKERY_HANDLE_DOMAIN=.localhost OAUTH_NONCE_SECRET=dev uv run fastapi dev`.

## tests

`uv run pytest -q` runs everything on the Worker fakes, including
`tests/test_server.py` (HTTP and the firehose through the ASGI stack, the SQL
translation, the fetch guard, S3 via moto). The whole suite also runs on the
server's storage:

```bash
ROOST_TEST_BACKEND=sqlite uv run pytest -q
ROOST_TEST_BACKEND=postgres ROOST_TEST_DATABASE_URL=postgresql://postgres@localhost/postgres uv run pytest -q
```

(The Postgres run creates and drops a database per test.)

## open before cutover

- **Websockets on FastAPI Cloud** are not documented either way. The first
  deploy should check `wss://<app>.fastapicloud.dev/xrpc/com.atproto.sync.subscribeRepos`
  before relays are pointed at it.
- **Scale to zero** (always on Hobby) means cold starts; a relay holding the
  firehose open keeps a replica up. Pro can pin a minimum of 1.
- **Handle resolution.** The Worker answers `*.roost.latha.org/.well-known/atproto-did`
  through a wildcard route. FastAPI Cloud custom domains are per host (Hobby: one),
  so handles need `_atproto` TXT records instead (`CLOUDFLARE_DNS_TOKEN`), or the
  wildcard route stays on Cloudflare.
- **Moving the data.** `scripts/migrate_host.py` (FROM=Worker, TO=FastAPI app)
  exports each account, imports it, and repoints its DID on PLC, with the same
  operator token on both hosts. Blobs stay where they are when both hosts use the
  same R2 bucket.
