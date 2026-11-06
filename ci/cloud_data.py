# SPDX-License-Identifier: MIT
# Copyright (c) 2026 sol pbc

"""cloud_data.py EXPR [ARG...]: read `fastapi cloud ... --json` output on stdin
and print EXPR evaluated with `data` bound to its "data"; exit 1 with the
CLI's message when it reported an error."""

import json
import sys

output = json.loads(sys.stdin.read())
if "error" in output:
    error = output["error"]
    sys.exit(f"fastapi cloud: {error.get('code')}: {error.get('message')}")
data = output["data"]
print(eval(sys.argv[1], {"data": data, "sys": sys}))
