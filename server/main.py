# SPDX-License-Identifier: MIT
# Copyright (c) 2026 sol pbc

"""FastAPI entrypoint (`fastapi dev` from server/, or the bundle
ci/fastapi-deploy.sh uploads to FastAPI Cloud). The roost package and public/
come from the repository root (../), or from beside this file in the deploy
bundle, which ships them next to it."""

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE if (HERE / "src" / "roost").is_dir() else HERE.parent
if not (ROOT / "src" / "roost").is_dir():
    raise RuntimeError(f"roost package not found in {HERE / 'src'} or {HERE.parent / 'src'}")
sys.path.insert(0, str(ROOT / "src"))

from roost_server.app import create_app  # noqa: E402

app = create_app(public_dir=ROOT / "public")
