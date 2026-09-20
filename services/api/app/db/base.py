"""Shared SQLAlchemy declarative base.

This module exists to provide a stable import path (``app.db.base``)
for model modules and Alembic, while reusing the same Base object
created in ``app.db.session``.
"""

from app.db.session import Base

__all__ = ["Base"]
