"""The API for the end-to-end tests (../3dcapconnectfrontend/e2e), on a brand-new database.

    uv run python scripts/e2e_server.py [--port 8000]

Drops and recreates the `capstoneconnect_e2e` database on the server in DATABASE_URL (.env), runs
every migration, seeds the demo data, then serves the API with uploads in `.e2e/uploads`. Reset
codes are returned to the app (ALLOW_DEV_CODE) and demo login is off, as on a real deployment.
The per-IP limits on sign-in and sign-up are raised, because every test runs from 127.0.0.1;
the per-number limits stay as configured.
"""

import argparse
import os
import re
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

DB_NAME = "capstoneconnect_e2e"


def _base_url() -> str:
    env = (ROOT / ".env").read_text(encoding="utf-8") if (ROOT / ".env").exists() else ""
    match = re.search(r"(?m)^DATABASE_URL=(.+)$", env)
    url = os.environ.get("DATABASE_URL") or (match.group(1).strip() if match else "")
    if not url:
        sys.exit("Set DATABASE_URL in .env (uv run python scripts/local_postgres.py writes it)")
    return url


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--production-like", action="store_true",
                        help="HTTPS behind the test proxy: Secure cookies, a random SECRET_KEY, no dev codes")
    parser.add_argument("--workers", type=int, default=1, help="uvicorn worker processes (the load test uses 2)")
    parser.add_argument("--database", default=DB_NAME, help="the throwaway database to (re)create")
    args = parser.parse_args()
    db_name = args.database
    if not db_name.replace("_", "").isalnum():
        sys.exit("--database: letters, digits and _ only")

    base = _base_url()
    url = re.sub(r"/[^/?]+(\?|$)", f"/{db_name}\\1", base, count=1)

    import psycopg

    admin_url = base.replace("postgresql+psycopg", "postgresql")
    with psycopg.connect(admin_url, autocommit=True) as conn:
        conn.execute(f"DROP DATABASE IF EXISTS {db_name} WITH (FORCE)")
        conn.execute(f"CREATE DATABASE {db_name}")

    uploads = ROOT / ".e2e" / f"uploads-{db_name}"
    shutil.rmtree(uploads, ignore_errors=True)
    uploads.mkdir(parents=True)

    os.environ.update({
        "DATABASE_URL": url,
        "UPLOAD_DIR": str(uploads),
        "ALLOW_DEV_CODE": "true",
        "DEMO_LOGIN": "false",
        "SMS_PROVIDER": "console",
        "GITHUB_TOKEN": "",
        "ADMIN_EMAIL": "",
        "ADMIN_PASSWORD": "",
        "LOGIN_LIMIT_PER_IP": "500",
        "SIGNUP_LIMIT_PER_IP": "500",
        "RESET_LIMIT_PER_IP": "500",
        "VERIFY_LIMIT_PER_IP": "500",
        "PUBLIC_STATS_LIMIT_PER_IP": "100000",
        "CORS_ORIGINS": '["http://localhost:3000","http://127.0.0.1:3000","http://localhost:3100"]',
        "PUBLIC_BASE_URL": f"http://localhost:{args.port}",
    })

    if args.production_like:
        import secrets

        # As on a real HTTPS deployment (the API refuses to start otherwise).
        os.environ.update({
            "COOKIE_SECURE": "true",
            "SECRET_KEY": secrets.token_urlsafe(48),
            "ALLOW_DEV_CODE": "false",
            "DEMO_LOGIN": "false",
            "SMS_PROVIDER": "console",
            "PUBLIC_BASE_URL": "https://localhost:8443",
            "CORS_ORIGINS": '["https://localhost:3443","https://localhost:3543"]',
        })
        from app.config import get_settings

        get_settings.cache_clear()

    from alembic import command
    from alembic.config import Config

    command.upgrade(Config(str(ROOT / "alembic.ini")), "head")

    from app.db import SessionLocal
    from app.seed import seed
    from app.services.admin import create_admin

    with SessionLocal() as db:
        seed(db)
        # The admin portal tests sign in with these (local test accounts on a throwaway database).
        create_admin(db, "e2e-admin@example.test", "E2E Admin", "e2e-admin-password", "admin")
        create_admin(db, "e2e-viewer@example.test", "E2E Viewer", "e2e-viewer-password", "viewer")
        db.commit()
    print(f"E2E database {db_name} ready", flush=True)

    import uvicorn

    # Behind the proxy (e2e/https/proxy.mjs on 127.0.0.1): its X-Forwarded-* headers are believed.
    uvicorn.run("app.main:app", host="127.0.0.1", port=args.port, log_level="warning", workers=args.workers,
                proxy_headers=True, forwarded_allow_ips="127.0.0.1")


if __name__ == "__main__":
    main()
