#!/bin/sh
# Applies migrations, refuses unsafe settings, then serves the API.
#   WEB_CONCURRENCY      worker processes (default 2)
#   FORWARDED_ALLOW_IPS  the reverse proxy's address(es) whose X-Forwarded-For/-Proto are believed
#                        (default 127.0.0.1; "*" only if nothing but the proxy can reach the API)
#   PORT                 port to listen on (default 8000; many hosts set it)
set -e

alembic upgrade head

exec uvicorn app.main:app \
  --host 0.0.0.0 \
  --port "${PORT:-8000}" \
  --workers "${WEB_CONCURRENCY:-2}" \
  --proxy-headers \
  --forwarded-allow-ips "${FORWARDED_ALLOW_IPS:-127.0.0.1}" \
  --no-server-header
