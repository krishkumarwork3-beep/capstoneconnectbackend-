"""Runs a local PostgreSQL for development without installing one (the `pgserver` dev package).

    uv run python scripts/local_postgres.py          # start it and write DATABASE_URL to .env
    uv run python scripts/local_postgres.py --stop   # stop it

The data lives in .pgdata/. With a real PostgreSQL (installed, Docker, or hosted) you don't need
this: put its URL in .env as DATABASE_URL instead.
"""

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / ".pgdata"
ENV = ROOT / ".env"


def write_env(url: str) -> None:
    text = ENV.read_text(encoding="utf-8") if ENV.exists() else (ROOT / ".env.example").read_text(encoding="utf-8")
    line = f"DATABASE_URL={url}"
    text = re.sub(r"(?m)^DATABASE_URL=.*$", line, text) if re.search(r"(?m)^DATABASE_URL=", text) else f"{line}\n{text}"
    ENV.write_text(text, encoding="utf-8")


def main() -> None:
    import pgserver

    server = pgserver.get_server(str(DATA), cleanup_mode=None)
    if "--stop" in sys.argv:
        server.cleanup()
        print("Stopped.")
        return
    # Through psycopg rather than server.psql(): pgserver runs psql through the shell unquoted,
    # which breaks when the project path contains a space.
    import psycopg

    port = re.search(r":(\d+)/", server.get_uri()).group(1)
    with psycopg.connect(f"postgresql://postgres@127.0.0.1:{port}/postgres", autocommit=True) as conn:
        for name in ("capstoneconnect", "capstoneconnect_test"):
            if not conn.execute("select 1 from pg_database where datname = %s", (name,)).fetchone():
                conn.execute(f'create database "{name}"')
    url = f"postgresql+psycopg://postgres@127.0.0.1:{port}/capstoneconnect"
    write_env(url)
    print(f"PostgreSQL is running: {url}")
    print("Wrote DATABASE_URL to .env")


if __name__ == "__main__":
    main()
