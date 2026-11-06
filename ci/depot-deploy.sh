#!/usr/bin/env bash
# Forge job: run the FastAPI Cloud deploy on a Depot builder (`depot build`),
# because the forge runner itself hangs on long steps. Needs the DEPOT_TOKEN and
# DEPOT_PROJECT_ID secrets plus the deploy secrets ci/fastapi-deploy.sh reads.
set -euo pipefail
REPO=$(cd "$(dirname "$0")/.." && pwd)
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
: "${DEPOT_TOKEN:?DEPOT_TOKEN secret is not set}" "${DEPOT_PROJECT_ID:?DEPOT_PROJECT_ID secret is not set}"

# The depot CLI: the latest release's linux tarball (no curl on the runner).
python3 - "$WORK/bin" <<'PY'
import io, os, sys, tarfile, urllib.request
latest = urllib.request.urlopen("https://github.com/depot/cli/releases/latest", timeout=60).url
version = latest.rstrip("/").rsplit("/", 1)[1]
url = f"https://github.com/depot/cli/releases/download/{version}/depot_{version.lstrip('v')}_linux_amd64.tar.gz"
data = urllib.request.urlopen(url, timeout=120).read()
os.makedirs(sys.argv[1], exist_ok=True)
with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
    member = next(m for m in archive.getmembers() if m.isfile() and m.name.rsplit("/", 1)[-1] == "depot")
    with open(os.path.join(sys.argv[1], "depot"), "wb") as out:
        out.write(archive.extractfile(member).read())
os.chmod(os.path.join(sys.argv[1], "depot"), 0o755)
print(f"depot {version}")
PY

# The deploy secrets as a shell env file, mounted into the one RUN step.
python3 - "$WORK/deploy.env" <<'PY'
import os, shlex, sys
names = ["FASTAPI_TOKEN", "FASTAPI_CLOUD_APP_ID", "ROOKERY_OPERATOR_TOKEN", "DNS_TOKEN", "OAUTH_NONCE_SECRET",
         "ROOKERY_HOSTNAME", "ROOKERY_HANDLE_DOMAIN", "ROOKERY_PLC_URL", "DATABASE_URL",
         "S3_BUCKET", "S3_ENDPOINT_URL", "S3_ACCESS_KEY_ID", "S3_SECRET_ACCESS_KEY", "ROOKERY_OPERATOR_TOKEN_SHA256"]
with open(sys.argv[1], "w") as out:
    for name in names:
        if os.environ.get(name):
            out.write(f"{name}={shlex.quote(os.environ[name])}\n")
PY

"$WORK/bin/depot" build --project "$DEPOT_PROJECT_ID" --progress plain \
  -f "$REPO/ci/deploy.Dockerfile" --secret id=deploy_env,src="$WORK/deploy.env" \
  --build-arg DEPLOY_ID="$(python3 -c 'import uuid; print(uuid.uuid4())')" "$REPO"
