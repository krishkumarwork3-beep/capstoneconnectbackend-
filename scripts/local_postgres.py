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
    for name in ("capstoneconnect", "capstoneconnect_test"):
        exists = server.psql(f"select 1 from pg_database where datname = '{name}';")
        if "(1 row)" not in exists:
            server.psql(f"create database {name};")
    port = re.search(r"\d+", server.psql("show port;").split("\n", 2)[2]).group(0)
    url = f"postgresql+psycopg://postgres@127.0.0.1:{port}/capstoneconnect"
    write_env(url)
    print(f"PostgreSQL is running: {url}")
    print("Wrote DATABASE_URL to .env")


if __name__ == "__main__":
    main()
