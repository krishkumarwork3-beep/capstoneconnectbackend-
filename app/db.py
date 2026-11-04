"""Database engine and session. One session per request (see `get_db`)."""

from collections.abc import Iterator

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from app.config import get_settings


class Base(DeclarativeBase):
    pass


_settings = get_settings()
# Every statement is cut off after DB_STATEMENT_TIMEOUT_MS, and a transaction left idle (a stuck
# request) after twice that: no single query or request can hold the database for long.
engine = create_engine(
    _settings.database_url,
    pool_pre_ping=True,
    connect_args={"options": f"-c statement_timeout={_settings.db_statement_timeout_ms} "
                             f"-c idle_in_transaction_session_timeout={_settings.db_statement_timeout_ms * 2}"},
)
# Committed objects are reloaded on next access, so a response never shows stale membership.
SessionLocal = sessionmaker(bind=engine)


def get_db() -> Iterator[Session]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
