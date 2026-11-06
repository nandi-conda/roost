# SPDX-License-Identifier: MIT
# Copyright (c) 2026 sol pbc

"""Blob bytes outside Cloudflare: a Postgres table (the default when
DATABASE_URL is set), any S3-compatible bucket (R2 itself works, through its
S3 API), or a local directory.

All are synchronous; `AsyncBlobs` gives roost.app the async R2 shape
(get/put/list/delete) by running them in a worker thread, and `InlineBlobs`
gives the account code (already on a worker thread) the same shape without
another hop.
"""

import asyncio
import json
from pathlib import Path
from urllib.parse import quote, unquote

LIST_PAGE = 1000


class S3Blobs:
    def __init__(self, bucket: str, endpoint_url: str | None, region: str | None,
                 access_key_id: str, secret_access_key: str):
        import boto3
        from botocore.config import Config

        self._bucket = bucket
        self._client = boto3.client(
            "s3", endpoint_url=endpoint_url, region_name=region or "auto",
            aws_access_key_id=access_key_id, aws_secret_access_key=secret_access_key,
            config=Config(retries={"max_attempts": 3, "mode": "standard"}),
        )

    def get(self, key: str):
        try:
            found = self._client.get_object(Bucket=self._bucket, Key=key)
        except self._client.exceptions.NoSuchKey:
            return None
        return found["Body"].read(), found.get("ContentType")

    def put(self, key: str, data: bytes, content_type: str) -> None:
        self._client.put_object(Bucket=self._bucket, Key=key, Body=bytes(data), ContentType=content_type)

    def list(self, prefix: str, cursor: str | None):
        options = {"Bucket": self._bucket, "Prefix": prefix, "MaxKeys": LIST_PAGE}
        if cursor:
            options["ContinuationToken"] = cursor
        listed = self._client.list_objects_v2(**options)
        keys = [item["Key"] for item in listed.get("Contents", [])]
        if listed.get("IsTruncated"):
            if not listed.get("NextContinuationToken"):
                raise RuntimeError("S3 blob listing was truncated without a continuation token")
            return keys, listed["NextContinuationToken"]
        return keys, None

    def delete(self, keys: list[str]) -> None:
        for start in range(0, len(keys), LIST_PAGE):
            chunk = keys[start:start + LIST_PAGE]
            result = self._client.delete_objects(
                Bucket=self._bucket, Delete={"Objects": [{"Key": key} for key in chunk], "Quiet": True},
            )
            if result.get("Errors"):
                raise RuntimeError(f"S3 delete failed for {len(result['Errors'])} blob(s)")


class PostgresBlobs:
    """roost_blobs.blobs in the same database as everything else. Blobs are
    capped at roost.app.MAX_BLOB_BYTES (60 MB), well under bytea's 1 GB.
    Its own small pool: account calls hold a connection while they put blobs,
    so sharing theirs could starve the pool."""

    def __init__(self, url: str, max_connections: int = 4):
        from psycopg_pool import ConnectionPool

        self._pool = ConnectionPool(url, min_size=1, max_size=max_connections, open=True,
                                    kwargs={"prepare_threshold": None})
        with self._pool.connection() as connection:
            connection.execute('CREATE SCHEMA IF NOT EXISTS roost_blobs')
            connection.execute('CREATE TABLE IF NOT EXISTS roost_blobs.blobs ('
                               'key TEXT COLLATE "C" PRIMARY KEY, data BYTEA NOT NULL, content_type TEXT)')

    def get(self, key: str):
        with self._pool.connection() as connection:
            row = connection.execute("SELECT data, content_type FROM roost_blobs.blobs WHERE key = %s",
                                     (key,)).fetchone()
        return None if row is None else (bytes(row[0]), row[1])

    def put(self, key: str, data: bytes, content_type: str) -> None:
        with self._pool.connection() as connection:
            connection.execute(
                "INSERT INTO roost_blobs.blobs (key, data, content_type) VALUES (%s, %s, %s) "
                "ON CONFLICT (key) DO UPDATE SET data = excluded.data, content_type = excluded.content_type",
                (key, bytes(data), content_type))

    def list(self, prefix: str, cursor: str | None):
        # starts_with, not LIKE: keys may hold % or _.
        with self._pool.connection() as connection:
            rows = connection.execute(
                "SELECT key FROM roost_blobs.blobs WHERE starts_with(key, %s) AND key > %s "
                "ORDER BY key LIMIT %s", (prefix, cursor or "", LIST_PAGE + 1)).fetchall()
        keys = [row[0] for row in rows[:LIST_PAGE]]
        return keys, (keys[-1] if len(rows) > LIST_PAGE else None)

    def delete(self, keys: list[str]) -> None:
        with self._pool.connection() as connection:
            connection.execute("DELETE FROM roost_blobs.blobs WHERE key = ANY(%s)", (list(keys),))

    def close(self) -> None:
        self._pool.close()


class DirectoryBlobs:
    """One file per key (its name the percent-encoded key) plus a .type file."""

    def __init__(self, root: str):
        self._root = Path(root)
        self._root.mkdir(parents=True, exist_ok=True)

    def _path(self, key: str) -> Path:
        if not key or key.startswith("/") or ".." in key.split("/"):
            raise ValueError(f"Invalid blob key: {key!r}")
        return self._root / quote(key, safe="")

    def get(self, key: str):
        path = self._path(key)
        if not path.is_file():
            return None
        meta = path.with_name(path.name + ".type")
        content_type = json.loads(meta.read_text())["contentType"] if meta.is_file() else None
        return path.read_bytes(), content_type

    def put(self, key: str, data: bytes, content_type: str) -> None:
        path = self._path(key)
        path.with_name(path.name + ".type").write_text(json.dumps({"contentType": content_type}))
        path.write_bytes(bytes(data))

    def list(self, prefix: str, cursor: str | None):
        keys = sorted(
            key for key in (unquote(path.name) for path in self._root.iterdir() if not path.name.endswith(".type"))
            if key.startswith(prefix) and (cursor is None or key > cursor)
        )
        page = keys[:LIST_PAGE]
        return page, (page[-1] if len(keys) > LIST_PAGE else None)

    def delete(self, keys: list[str]) -> None:
        for key in keys:
            path = self._path(key)
            path.unlink(missing_ok=True)
            path.with_name(path.name + ".type").unlink(missing_ok=True)


class AsyncBlobs:
    def __init__(self, store):
        self._store = store

    async def get(self, key):
        return await asyncio.to_thread(self._store.get, key)

    async def put(self, key, data, content_type):
        await asyncio.to_thread(self._store.put, key, data, content_type)

    async def list(self, prefix, cursor):
        return await asyncio.to_thread(self._store.list, prefix, cursor)

    async def delete(self, keys):
        await asyncio.to_thread(self._store.delete, keys)


class InlineBlobs:
    def __init__(self, store):
        self._store = store

    async def get(self, key):
        return self._store.get(key)

    async def put(self, key, data, content_type):
        self._store.put(key, data, content_type)

    async def list(self, prefix, cursor):
        return self._store.list(prefix, cursor)

    async def delete(self, keys):
        self._store.delete(keys)


def open_blobs(environ: dict):
    """S3 when S3_BUCKET is set (S3_ENDPOINT_URL for R2 or another provider), else
    Postgres when DATABASE_URL is set, else ROOST_BLOB_DIR."""
    bucket = environ.get("S3_BUCKET")
    if bucket:
        missing = [name for name in ("S3_ACCESS_KEY_ID", "S3_SECRET_ACCESS_KEY") if not environ.get(name)]
        if missing:
            raise ValueError(f"S3_BUCKET is set but {', '.join(missing)} is not")
        return S3Blobs(bucket, environ.get("S3_ENDPOINT_URL"), environ.get("S3_REGION"),
                       environ["S3_ACCESS_KEY_ID"], environ["S3_SECRET_ACCESS_KEY"])
    if environ.get("DATABASE_URL"):
        return PostgresBlobs(environ["DATABASE_URL"])
    directory = environ.get("ROOST_BLOB_DIR") or (
        str(Path(environ["ROOST_DATA_DIR"]) / "blobs") if environ.get("ROOST_DATA_DIR") else None
    )
    if not directory:
        raise ValueError("Set DATABASE_URL, S3_BUCKET (+ S3_ACCESS_KEY_ID, S3_SECRET_ACCESS_KEY, S3_ENDPOINT_URL) or ROOST_BLOB_DIR")
    return DirectoryBlobs(directory)
