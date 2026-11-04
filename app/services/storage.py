"""Where uploaded files live: local disk or S3-compatible object storage, chosen by STORAGE_BACKEND.

Files are always served through the API (app.routers.files), whatever the backend, so the
private-file rules hold everywhere: avatars public, résumés for signed-in users, chat attachments
for the conversation's participants. Keys are "{purpose}/{name}" (e.g. "resume/res_….pdf").

- local: UPLOAD_DIR on a persistent disk (the default; fine for one server or a mounted volume).
- s3:    any S3 API: AWS S3, Cloudflare R2, Backblaze B2, MinIO (S3_ENDPOINT_URL for non-AWS).
         Use it on hosts without a persistent disk, or with more than one server.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Protocol

from app.config import get_settings


class Storage(Protocol):
    def put(self, key: str, data: bytes, content_type: str) -> None: ...
    def get(self, key: str) -> bytes | None: ...
    def exists(self, key: str) -> bool: ...
    def size(self, key: str) -> int | None: ...
    def delete(self, key: str) -> bool: ...
    def keys(self) -> list[str]: ...


class LocalStorage:
    def __init__(self, root: Path):
        self.root = root

    def _path(self, key: str) -> Path:
        return self.root / key

    def put(self, key: str, data: bytes, content_type: str) -> None:
        path = self._path(key)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)

    def get(self, key: str) -> bytes | None:
        path = self._path(key)
        return path.read_bytes() if path.is_file() else None

    def exists(self, key: str) -> bool:
        return self._path(key).is_file()

    def size(self, key: str) -> int | None:
        path = self._path(key)
        return path.stat().st_size if path.is_file() else None

    def delete(self, key: str) -> bool:
        path = self._path(key)
        if not path.is_file():
            return False
        path.unlink()
        return True

    def keys(self) -> list[str]:
        if not self.root.exists():
            return []
        return sorted(p.relative_to(self.root).as_posix() for p in self.root.rglob("*") if p.is_file() and p.name != ".gitkeep")


class S3Storage:
    def __init__(self, bucket: str, *, endpoint_url: str | None, region: str | None, access_key: str | None,
                 secret_key: str | None, prefix: str = ""):
        import boto3

        self.bucket = bucket
        self.prefix = prefix.strip("/")
        self.client = boto3.client(
            "s3",
            endpoint_url=endpoint_url or None,
            region_name=region or None,
            aws_access_key_id=access_key or None,
            aws_secret_access_key=secret_key or None,
        )

    def _key(self, key: str) -> str:
        return f"{self.prefix}/{key}" if self.prefix else key

    def put(self, key: str, data: bytes, content_type: str) -> None:
        # Private objects: the API decides who may read them.
        self.client.put_object(Bucket=self.bucket, Key=self._key(key), Body=data, ContentType=content_type)

    def get(self, key: str) -> bytes | None:
        try:
            return self.client.get_object(Bucket=self.bucket, Key=self._key(key))["Body"].read()
        except self.client.exceptions.NoSuchKey:
            return None

    def _head(self, key: str) -> dict | None:
        from botocore.exceptions import ClientError

        try:
            return self.client.head_object(Bucket=self.bucket, Key=self._key(key))
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") in ("404", "NoSuchKey", "NotFound"):
                return None
            raise

    def exists(self, key: str) -> bool:
        return self._head(key) is not None

    def size(self, key: str) -> int | None:
        head = self._head(key)
        return int(head["ContentLength"]) if head else None

    def delete(self, key: str) -> bool:
        if not self.exists(key):
            return False
        self.client.delete_object(Bucket=self.bucket, Key=self._key(key))
        return True

    def keys(self) -> list[str]:
        found: list[str] = []
        paginator = self.client.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=self.bucket, Prefix=f"{self.prefix}/" if self.prefix else ""):
            for item in page.get("Contents", []):
                key = item["Key"]
                found.append(key[len(self.prefix) + 1:] if self.prefix else key)
        return sorted(found)


@lru_cache
def get_storage() -> Storage:
    s = get_settings()
    if s.storage_backend == "s3":
        return S3Storage(s.s3_bucket, endpoint_url=s.s3_endpoint_url, region=s.s3_region,
                         access_key=s.s3_access_key_id, secret_key=s.s3_secret_access_key, prefix=s.s3_prefix)
    return LocalStorage(s.upload_dir)
