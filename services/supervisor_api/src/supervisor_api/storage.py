"""Pluggable blob storage for long-retention evidence exports.

Two backends: local filesystem (default, for dev/tests) and S3
(requires `boto3` — add as optional dep before enabling in prod).
Select via STORAGE_BACKEND=local|s3. The evidence export endpoint
writes one JSON bundle per action to a durable store so that even if
the DB is pruned or corrupted, the signed bundle remains recoverable
for compliance retention (2-7 years for fintechs).
"""
from __future__ import annotations

import logging
import os
from pathlib import Path

log = logging.getLogger(__name__)


class StorageBackend:
    def put(self, key: str, body: bytes) -> str:
        """Store `body` at logical `key`, return a URL/URI that can retrieve it."""
        raise NotImplementedError

    def get(self, key: str) -> bytes:
        raise NotImplementedError


class LocalStorage(StorageBackend):
    def __init__(self, root: Path) -> None:
        self.root = root
        self.root.mkdir(parents=True, exist_ok=True)

    def put(self, key: str, body: bytes) -> str:
        path = self.root / key
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(body)
        return f"file://{path.absolute()}"

    def get(self, key: str) -> bytes:
        return (self.root / key).read_bytes()


class S3Storage(StorageBackend):  # pragma: no cover — requires boto3
    def __init__(self, bucket: str, prefix: str = "") -> None:
        import boto3

        self.bucket = bucket
        self.prefix = prefix.strip("/")
        self.client = boto3.client("s3")

    def put(self, key: str, body: bytes) -> str:
        full_key = f"{self.prefix}/{key}" if self.prefix else key
        self.client.put_object(Bucket=self.bucket, Key=full_key, Body=body, ContentType="application/json")
        return f"s3://{self.bucket}/{full_key}"

    def get(self, key: str) -> bytes:
        full_key = f"{self.prefix}/{key}" if self.prefix else key
        obj = self.client.get_object(Bucket=self.bucket, Key=full_key)
        return obj["Body"].read()


_backend: StorageBackend | None = None


def get_backend() -> StorageBackend:
    global _backend
    if _backend is not None:
        return _backend
    kind = os.environ.get("STORAGE_BACKEND", "local").lower()
    if kind == "s3":
        bucket = os.environ["AWS_S3_BUCKET"]
        prefix = os.environ.get("AWS_S3_PREFIX", "evidence")
        _backend = S3Storage(bucket, prefix)
        log.info("evidence storage: s3://%s/%s", bucket, prefix)
    else:
        root = Path(os.environ.get("STORAGE_PATH", "/tmp/aic-evidence"))
        _backend = LocalStorage(root)
        log.info("evidence storage: local at %s", root)
    return _backend


def reset_backend() -> None:
    """For tests."""
    global _backend
    _backend = None
