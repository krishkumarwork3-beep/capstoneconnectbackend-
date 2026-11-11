# CapstoneConnect API. Works on any host that runs containers (Render, Railway, Fly.io, a VPS, …).
#
#   docker build -t capstoneconnect-api .
#   docker run --env-file .env.production -p 8000:8000 -v cc-uploads:/data/uploads capstoneconnect-api
#
# On start it applies the database migrations, then serves with 2 workers. Settings come from the
# environment (see .env.production.example); nothing secret is baked into the image.
FROM python:3.12.11-slim-bookworm AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PROJECT_ENVIRONMENT=/app/.venv

# pg_dump / pg_restore for scripts/db_backup.py (the PostgreSQL 16 client).
RUN apt-get update \
    && apt-get install -y --no-install-recommends postgresql-client \
    && rm -rf /var/lib/apt/lists/*
COPY --from=ghcr.io/astral-sh/uv:0.13.6 /uv /usr/local/bin/uv

WORKDIR /app
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project
COPY app ./app
COPY alembic ./alembic
COPY alembic.ini ./
COPY scripts/db_backup.py scripts/migrate_uploads.py ./scripts/
COPY docker-entrypoint.sh ./
RUN chmod +x docker-entrypoint.sh \
    && useradd --create-home --uid 10001 app \
    && mkdir -p /data/uploads && chown -R app /data /app

USER app
ENV PATH="/app/.venv/bin:$PATH" \
    UPLOAD_DIR=/data/uploads \
    PORT=8000
VOLUME ["/data/uploads"]
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s CMD python -c "import os,urllib.request; urllib.request.urlopen(f'http://127.0.0.1:{os.environ.get(\"PORT\",\"8000\")}/api/health', timeout=4)"
ENTRYPOINT ["./docker-entrypoint.sh"]
