#!/usr/bin/env bash
# Deploy server/ (roost as a FastAPI app) to the FastAPI Cloud app "roost".
# Runs from the fileapi forge (.forge/jobs.toml) on every push to main; the
# Cloudflare Worker is deployed separately (GitHub Actions) and untouched here.
#
# Forge secrets (repo nandi.uk/roost):
#   FASTAPI_TOKEN        FastAPI Cloud user token (required)
#   DATABASE_URL         Postgres URL, e.g. Neon's pooled URL (required)
#   S3_BUCKET, S3_ENDPOINT_URL, S3_ACCESS_KEY_ID, S3_SECRET_ACCESS_KEY   blob bucket (required; R2 works)
#   OAUTH_NONCE_SECRET   (required), ROOKERY_OPERATOR_TOKEN_SHA256 (optional)
# Each secret is copied onto the app (as a FastAPI Cloud secret) before the deploy.
# ROOKERY_HOSTNAME defaults to the app's own <slug>.fastapicloud.dev host.
set -euo pipefail
APP_NAME=${APP_NAME:-roost}
TOKEN=${FASTAPI_TOKEN:?FASTAPI_TOKEN secret is not set (a FastAPI Cloud user token)}
REPO=$(cd "$(dirname "$0")/.." && pwd)
WORK=$(mktemp -d)

missing=()
for name in DATABASE_URL S3_BUCKET S3_ENDPOINT_URL S3_ACCESS_KEY_ID S3_SECRET_ACCESS_KEY OAUTH_NONCE_SECRET; do
  [ -n "${!name:-}" ] || missing+=("$name")
done
if [ ${#missing[@]} -gt 0 ]; then
  echo "missing forge secrets: ${missing[*]}" >&2
  exit 1
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
py() { uv run --frozen python -c "$@"; }

printf '{"access_token": "%s"}' "$TOKEN" > "$FASTAPI_CLOUD_CLI_CONFIG_DIR/auth.json"
team=$(fc cloud teams list --json | py 'import json,sys; print(json.loads(sys.stdin.read())["teams"][0]["id"])')
apps=$(fc cloud apps list --json --team-id "$team")
read -r app slug < <(py 'import json,sys
for a in json.loads(sys.stdin.read())["apps"]:
    if a.get("name") == sys.argv[1] or a.get("slug") == sys.argv[1]:
        print(a["id"], a.get("slug") or a["name"]); break' "$APP_NAME" <<<"$apps") || true
if [ -z "${app:-}" ]; then
  echo "creating app $APP_NAME"
  out=$(fc cloud apps create --team-id "$team" --name "$APP_NAME" --json)
  read -r app slug < <(py 'import json,sys; d=json.loads(sys.stdin.read()); d=d.get("app", d); print(d["id"], d.get("slug") or d["name"])' <<<"$out")
fi
host=${ROOKERY_HOSTNAME:-$slug.fastapicloud.dev}
echo "app $app at https://$host"

setvar() {  # name value [--secret]
  printf '%s' "$2" | fc cloud env set --app-id "$app" ${3:-} --value-stdin --no-redeploy "$1" >/dev/null
  echo "set $1"
}
setvar ROOKERY_HOSTNAME "$host"
setvar ROOKERY_HANDLE_DOMAIN "${ROOKERY_HANDLE_DOMAIN:-.$host}"
setvar ROOKERY_PLC_URL "${ROOKERY_PLC_URL:-https://plc.directory}"
setvar S3_BUCKET "$S3_BUCKET"
setvar S3_ENDPOINT_URL "$S3_ENDPOINT_URL"
for name in DATABASE_URL S3_ACCESS_KEY_ID S3_SECRET_ACCESS_KEY OAUTH_NONCE_SECRET ROOKERY_OPERATOR_TOKEN_SHA256; do
  [ -n "${!name:-}" ] && setvar "$name" "${!name}" --secret
done

fc deploy --app-id "$app"
