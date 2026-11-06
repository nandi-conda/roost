#!/usr/bin/env bash
# Deploy server/ (roost as a FastAPI app) to the FastAPI Cloud app "roost".
# Runs from the fileapi forge (.forge/jobs.toml) on every push to main; the
# Cloudflare Worker is deployed separately (GitHub Actions) and untouched here.
#
# Forge secrets (repo nandi.uk/roost):
#   FASTAPI_TOKEN        FastAPI Cloud user token (required)
#   DATABASE_URL         Postgres URL, e.g. Neon's pooled URL
#   S3_BUCKET, S3_ENDPOINT_URL, S3_ACCESS_KEY_ID, S3_SECRET_ACCESS_KEY   blob bucket (R2 works)
#   OAUTH_NONCE_SECRET, ROOKERY_OPERATOR_TOKEN_SHA256
# Each secret is copied onto the app (as a FastAPI Cloud secret) before the deploy.
# Without DATABASE_URL / S3_BUCKET the app runs on SQLite and blob files under
# /tmp/roost: EPHEMERAL, lost on every restart or redeploy, one copy per replica.
# Without OAUTH_NONCE_SECRET one is generated once and kept on the app.
# ROOKERY_HOSTNAME defaults to the app's own <slug>.fastapicloud.dev host.
set -euo pipefail
APP_NAME=${APP_NAME:-roost}
TOKEN=${FASTAPI_TOKEN:?FASTAPI_TOKEN secret is not set (a FastAPI Cloud user token)}
REPO=$(cd "$(dirname "$0")/.." && pwd)
WORK=$(mktemp -d)

if [ -n "${S3_BUCKET:-}" ]; then
  for name in S3_ENDPOINT_URL S3_ACCESS_KEY_ID S3_SECRET_ACCESS_KEY; do
    [ -n "${!name:-}" ] || { echo "S3_BUCKET is set but $name is not" >&2; exit 1; }
  done
fi

if ! command -v uv >/dev/null; then
  python3 "$REPO/ci/fetch.py" https://github.com/astral-sh/uv/releases/latest/download/uv-x86_64-unknown-linux-gnu.tar.gz "$WORK/bin" 1
  export PATH="$WORK/bin:$PATH"
fi
uv --version

# The upload: server/ plus the roost package and static files it serves.
BUNDLE="$WORK/bundle"
mkdir -p "$BUNDLE/src"
cp -r "$REPO/server/." "$BUNDLE/"
rm -rf "$BUNDLE/.venv"
cp -r "$REPO/src/roost" "$BUNDLE/src/roost"
cp -r "$REPO/public" "$BUNDLE/public"
find "$BUNDLE" -name __pycache__ -prune -exec rm -rf {} +

export CI=true
export FASTAPI_CLOUD_CLI_CONFIG_DIR="$WORK/fastapi"
export UV_PROJECT_ENVIRONMENT="$WORK/venv"  # keep the venv out of the upload
export UV_CACHE_DIR="$WORK/uv-cache"
unset VIRTUAL_ENV
mkdir -p "$FASTAPI_CLOUD_CLI_CONFIG_DIR"
cd "$BUNDLE"
uv sync --frozen -q
fc() { uv run --frozen fastapi "$@"; }

# `--json` prints {"data": ...} or {"error": {"code", "message"}}; cloud_data.py prints one field of it.
data() { uv run --frozen python "$REPO/ci/cloud_data.py" "$@"; }
token_kind=$(python3 - "$TOKEN" <<'PY'
import base64, json, sys, time
parts = sys.argv[1].split(".")
try:
    claims = json.loads(base64.urlsafe_b64decode(parts[1] + "=" * (-len(parts[1]) % 4))) if len(parts) == 3 else None
except ValueError:
    claims = None
if claims is None:
    print("deploy")
elif claims.get("exp") and claims["exp"] <= time.time():
    print("expired")
else:
    print("user")
PY
)
echo "FASTAPI_TOKEN looks like a $token_kind token"
if [ "$token_kind" = expired ]; then
  echo "FASTAPI_TOKEN is an expired user token: log in again (fastapi login) and store the new one" >&2
  exit 1
fi
if [ "$token_kind" = user ]; then
  printf '{"access_token": "%s"}' "$TOKEN" > "$FASTAPI_CLOUD_CLI_CONFIG_DIR/auth.json"
  team=$(fc cloud teams list --json | data 'data["teams"][0]["id"]')
  apps=$(fc cloud apps list --json --team-id "$team")
  read -r app slug url < <(data 'next((" ".join([a["id"], a["slug"], a.get("url") or "-"]) for a in data["apps"] if a["name"] == sys.argv[2] or a["slug"] == sys.argv[2]), "")' "$APP_NAME" <<<"$apps") || true
  if [ -z "${app:-}" ]; then
    echo "creating app $APP_NAME"
    read -r app slug < <(fc cloud apps create --team-id "$team" --name "$APP_NAME" --json | data 'data["app"]["id"] + " " + data["app"]["slug"]')
    url=-
  fi
  [ -n "${app:-}" ] || { echo "could not find or create app $APP_NAME" >&2; exit 1; }
  if [ "${url:--}" = "-" ]; then url="https://$slug.fastapicloud.dev"; fi
else
  # An app deploy token deploys one app; FASTAPI_CLOUD_APP_ID names it.
  export FASTAPI_CLOUD_TOKEN=$TOKEN
  app=${FASTAPI_CLOUD_APP_ID:?FASTAPI_TOKEN is an app deploy token: also set the FASTAPI_CLOUD_APP_ID secret (the app id from the dashboard)}
  url="https://${ROOKERY_HOSTNAME:-$APP_NAME.fastapicloud.dev}"
fi
host=${ROOKERY_HOSTNAME:-$(python3 -c "import sys, urllib.parse; print(urllib.parse.urlsplit(sys.argv[1]).hostname)" "$url")}
echo "app $app at https://$host"

setvar() {  # name value [--secret]
  printf '%s' "$2" | fc cloud env set --app-id "$app" ${3:-} --value-stdin --no-redeploy "$1" >/dev/null
  echo "set $1"
}
setvar ROOKERY_HOSTNAME "$host"
setvar ROOKERY_HANDLE_DOMAIN "${ROOKERY_HANDLE_DOMAIN:-.$host}"
setvar ROOKERY_PLC_URL "${ROOKERY_PLC_URL:-https://plc.directory}"
if [ -z "${DATABASE_URL:-}" ] || [ -z "${S3_BUCKET:-}" ]; then
  echo "WARNING: no DATABASE_URL and/or S3_BUCKET secret: storage is EPHEMERAL (/tmp/roost), lost on restart"
  setvar ROOST_DATA_DIR /tmp/roost
fi
[ -n "${S3_BUCKET:-}" ] && setvar S3_BUCKET "$S3_BUCKET" && setvar S3_ENDPOINT_URL "$S3_ENDPOINT_URL"
for name in DATABASE_URL S3_ACCESS_KEY_ID S3_SECRET_ACCESS_KEY OAUTH_NONCE_SECRET ROOKERY_OPERATOR_TOKEN_SHA256; do
  if [ -n "${!name:-}" ]; then setvar "$name" "${!name}" --secret; fi
done
if [ -z "${OAUTH_NONCE_SECRET:-}" ] && ! fc cloud env list --app-id "$app" --json | grep -q '"OAUTH_NONCE_SECRET"'; then
  setvar OAUTH_NONCE_SECRET "$(python3 -c 'import secrets; print(secrets.token_hex(32))')" --secret
fi

fc deploy --app-id "$app"
