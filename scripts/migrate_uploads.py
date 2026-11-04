"""Copies uploaded files from local disk (UPLOAD_DIR) to S3-compatible storage (the S3_* settings).

    uv run python scripts/migrate_uploads.py            # copy what is missing in the bucket
    uv run python scripts/migrate_uploads.py --dry-run  # only list what would be copied

Then set STORAGE_BACKEND=s3 and restart the API. Links do not change (the database keeps paths
like /uploads/resume/res_….pdf, and the API serves them from whichever storage is configured).
Files already in the bucket are skipped, so it is safe to run again. Local files are kept.
"""

import argparse
import mimetypes
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


def migrate(source, target, dry_run: bool = False) -> tuple[int, int]:
    copied = skipped = 0
    for key in source.keys():
        if target.exists(key):
            skipped += 1
            continue
        if not dry_run:
            data = source.get(key)
            target.put(key, data, mimetypes.guess_type(key)[0] or "application/octet-stream")
        copied += 1
        print(("would copy " if dry_run else "copied ") + key)
    return copied, skipped


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    from app.config import get_settings
    from app.services.storage import LocalStorage, S3Storage

    s = get_settings()
    if not s.s3_bucket:
        sys.exit("Set S3_BUCKET (and S3_ENDPOINT_URL, S3_REGION, S3_ACCESS_KEY_ID, S3_SECRET_ACCESS_KEY) first.")
    source = LocalStorage(s.upload_dir)
    target = S3Storage(s.s3_bucket, endpoint_url=s.s3_endpoint_url, region=s.s3_region,
                       access_key=s.s3_access_key_id, secret_key=s.s3_secret_access_key, prefix=s.s3_prefix)
    copied, skipped = migrate(source, target, args.dry_run)
    print(f"{'Would copy' if args.dry_run else 'Copied'} {copied} file(s); {skipped} already in the bucket.")


if __name__ == "__main__":
    main()
