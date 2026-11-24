from __future__ import annotations

from collections.abc import Generator

from mosp.db.engine import application_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker

from app.core.config import settings

if not settings.database_url:
    # PostgreSQL is the only supported database, for running and for tests.
    raise RuntimeError("OSPMAE_DATABASE_URL is required (a PostgreSQL database)")

engine = application_engine(settings.database_url, sql_trace=settings.sql_trace)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


class Base(DeclarativeBase):
    """Typed declarative base so Mapped[] attributes type-check."""


def get_db() -> Generator:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
