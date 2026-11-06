#!/usr/bin/env bash
# Forge job (push to the "sync-identities" branch): scripts/sync_identities.py
# against roost.latha.org with the ROOKERY_OPERATOR_TOKEN secret: re-signs PLC
# documents and rewrites handle TXT records that are wrong.
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
uv run --frozen --no-dev --with httpx python scripts/sync_identities.py
