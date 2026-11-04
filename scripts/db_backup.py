"""Back up and restore the database with pg_dump / pg_restore (PostgreSQL's own tools).

    uv run python scripts/db_backup.py backup  [--out backups/capstoneconnect-20261104-0930.dump]
    uv run python scripts/db_backup.py restore backups/capstoneconnect-….dump --into postgresql+psycopg://…/new_db [--create]

- backup: a compressed custom-format dump of DATABASE_URL (schema, data and the Alembic version).
- restore: into an EMPTY database (--create makes it). Refuses to restore into DATABASE_URL's own
  database unless --force, so a typo can't overwrite production.

Uploaded files are not in the database: back up UPLOAD_DIR (or the S3 bucket) alongside.
The tools are found on PATH, or in the embedded PostgreSQL (scripts/local_postgres.py).
"""

import argparse
import os
import shutil
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


def tool(name: str) -> str:
    found = shutil.which(name)
    if found:
        return found
    try:
        import pgserver  # the embedded server used for development

        candidate = Path(pgserver.__file__).parent / "pginstall" / "bin" / (name + (".exe" if os.name == "nt" else ""))
        if candidate.exists():
            return str(candidate)
    except ImportError:
        pass
    sys.exit(f"{name} not found: install the PostgreSQL client tools (same major version as the server)")


def _libpq(url: str) -> tuple[str, dict]:
    """A libpq connection string without the password, and the password in the environment
    (so it never shows in the process list)."""
    from sqlalchemy.engine import make_url

    u = make_url(url)
    env = dict(os.environ)
    if u.password:
        env["PGPASSWORD"] = u.password
    dsn = u.set(drivername="postgresql", password=None).render_as_string(hide_password=False)
    return dsn, env


def backup(url: str, out: Path) -> Path:
    out.parent.mkdir(parents=True, exist_ok=True)
    dsn, env = _libpq(url)
    subprocess.run([tool("pg_dump"), "--format=custom", "--no-owner", "--no-privileges", "--file", str(out), dsn],
                   check=True, env=env)
    return out


def restore(dump: Path, into: str, create: bool = False) -> None:
    from sqlalchemy.engine import make_url

    target = make_url(into)
    if create:
        import psycopg

        admin_dsn, _ = _libpq(str(target.set(database="postgres")))
        password = target.password
        with psycopg.connect(admin_dsn, password=password, autocommit=True) if password else psycopg.connect(admin_dsn, autocommit=True) as conn:
            conn.execute(f'CREATE DATABASE "{target.database}"')
    dsn, env = _libpq(into)
    subprocess.run([tool("pg_restore"), "--no-owner", "--no-privileges", "--exit-on-error", "--dbname", dsn, str(dump)],
                   check=True, env=env)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    b = sub.add_parser("backup")
    b.add_argument("--out", type=Path)
    r = sub.add_parser("restore")
    r.add_argument("dump", type=Path)
    r.add_argument("--into", required=True, help="the target database URL (an empty database)")
    r.add_argument("--create", action="store_true", help="create the target database first")
    r.add_argument("--force", action="store_true", help="allow restoring into DATABASE_URL's database")
    args = parser.parse_args()

    from sqlalchemy.engine import make_url

    from app.config import get_settings

    url = get_settings().database_url
    if args.command == "backup":
        stamp = datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
        out = args.out or ROOT / "backups" / f"{make_url(url).database}-{stamp}.dump"
        print(f"Backed up to {backup(url, out)}")
        return
    same = make_url(args.into).set(password=None) == make_url(url).set(password=None)
    if same and not args.force:
        sys.exit("That is the live database (DATABASE_URL). Restore into a new one, or pass --force.")
    restore(args.dump, args.into, args.create)
    print(f"Restored {args.dump} into {make_url(args.into).database}")


if __name__ == "__main__":
    main()
