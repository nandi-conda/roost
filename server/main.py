# SPDX-License-Identifier: MIT
# Copyright (c) 2026 sol pbc

"""FastAPI Cloud entrypoint (`fastapi deploy` with server/ as the application
directory; locally `fastapi dev` from here). The roost package is the
repository's src/roost, the same code the Cloudflare Worker runs."""

import sys
from pathlib import Path

SRC = Path(__file__).resolve().parent.parent / "src"
if not (SRC / "roost").is_dir():
    raise RuntimeError(f"roost package not found at {SRC / 'roost'}: deploy the whole repository with server/ as the app directory")
sys.path.insert(0, str(SRC))

from roost_server.app import create_app  # noqa: E402

app = create_app()
