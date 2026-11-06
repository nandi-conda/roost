# SPDX-License-Identifier: MIT
# Copyright (c) 2026 sol pbc

"""fetch.py URL DEST_DIR [STRIP]: download a .tar.gz and unpack it (the forge
runner has no curl, git or gzip)."""

import io
import sys
import tarfile
import urllib.request

url, dest = sys.argv[1], sys.argv[2]
strip = int(sys.argv[3]) if len(sys.argv) > 3 else 0
data = urllib.request.urlopen(url, timeout=120).read()
with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
    members = []
    for member in archive.getmembers():
        parts = member.name.split("/")[strip:]
        if not parts or parts == [""]:
            continue
        member.name = "/".join(parts)
        members.append(member)
    archive.extractall(dest, members=members, filter="data")
print(f"fetched {url} ({len(data)} bytes)")
