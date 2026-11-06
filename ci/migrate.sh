#!/usr/bin/env bash
# Copy every account from the Cloudflare Worker into the FastAPI app
# (scripts/migrate_host.py). Runs from the forge on a push to the "cutover"
# branch; safe to re-run (accounts already moved are skipped).
set -euo pipefail
REPO=$(cd "$(dirname "$0")/.." && pwd)
WORK=$(mktemp -d)
: "${ROOKERY_OPERATOR_TOKEN:?ROOKERY_OPERATOR_TOKEN secret is not set}"
if ! command -v uv >/dev/null; then
  python3 "$REPO/ci/fetch.py" https://github.com/astral-sh/uv/releases/latest/download/uv-x86_64-unknown-linux-gnu.tar.gz "$WORK/bin" 1
  export PATH="$WORK/bin:$PATH"
fi
export UV_PROJECT_ENVIRONMENT="$WORK/venv" UV_CACHE_DIR="$WORK/uv-cache"
cd "$REPO"
FROM=${FROM:-https://roost.latha.org} TO=${TO:-https://roost.fastapicloud.dev} \
  uv run --frozen --no-dev --with httpx python scripts/migrate_host.py
