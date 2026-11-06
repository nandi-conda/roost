# SPDX-License-Identifier: MIT
# Copyright (c) 2026 sol pbc

"""Print the id of the one app a FastAPI Cloud deploy token (FASTAPI_CLOUD_TOKEN)
can see, with diagnostics on stderr; never prints the token."""

import sys

from fastapi_cloud_cli.api.client import APIClient

with APIClient(use_deploy_token=True) as client:
    response = client.get("/apps/")
    print(f"GET /apps/ -> {response.status_code}", file=sys.stderr)
    if response.status_code != 200:
        sys.exit(response.text[:300])
    body = response.json()
    apps = body.get("data", body) if isinstance(body, dict) else body
    for app in apps:
        print(f"  app {app.get('id')} name={app.get('name')} slug={app.get('slug')} url={app.get('url')}", file=sys.stderr)
    if len(apps) != 1:
        sys.exit(f"the token sees {len(apps)} apps; set FASTAPI_CLOUD_APP_ID")
    print(apps[0]["id"], apps[0].get("slug") or "-", apps[0].get("url") or "-")
