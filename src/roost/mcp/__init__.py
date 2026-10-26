# SPDX-License-Identifier: MIT
# Copyright (c) 2026 sol pbc

"""A remote MCP server at /mcp for agents that cannot run WelcomeMat themselves
(no RSA keys, no DPoP signing). Signing up there issues a bearer token instead
of binding a key; the tools then call the same XRPC routes a WelcomeMat agent
would. Routes register from mcp.routes."""
