"""Migration-chain contracts.

A fresh installation builds its database by replaying the Alembic chain, so
the chain must end in exactly the schema the models declare, run backwards to
an empty database, and never build tables from the live models: a revision
that calls ``Base.metadata.create_all`` creates whatever the models say on the
day it runs, so two installations at the same revision could differ.
"""

from __future__ import annotations

import ast
from pathlib import Path

from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.config import Config
from alembic.migration import MigrationContext
from alembic.script import ScriptDirectory
from app.db.session import Base, engine
from sqlalchemy import inspect, text

_API_ROOT = Path(__file__).resolve().parents[1]
_VERSIONS = _API_ROOT / "alembic" / "versions"


def _config() -> Config:
    cfg = Config(str(_API_ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(_API_ROOT / "alembic"))
    return cfg


def _empty_database() -> None:
    Base.metadata.drop_all(engine)
    with engine.begin() as conn:
        conn.execute(text("DROP TABLE IF EXISTS alembic_version"))


def test_the_chain_is_linear():
    script = ScriptDirectory.from_config(_config())
    assert len(script.get_heads()) == 1


def test_the_chain_builds_exactly_the_models_and_runs_back_to_nothing():
    _empty_database()
    try:
        command.upgrade(_config(), "head")
        with engine.connect() as conn:
            differences = compare_metadata(
                MigrationContext.configure(conn), Base.metadata
            )
        assert differences == []

        command.downgrade(_config(), "base")
        left = set(inspect(engine).get_table_names()) - {"alembic_version"}
        assert left == set()
    finally:
        _empty_database()
        Base.metadata.create_all(engine)


def _calls_create_all(tree: ast.AST) -> bool:
    return any(
        isinstance(node, ast.Attribute) and node.attr in {"create_all", "drop_all"}
        for node in ast.walk(tree)
    )


def _imports_models(tree: ast.AST) -> bool:
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and (node.module or "").startswith("app"):
            return True
        if isinstance(node, ast.Import) and any(
            alias.name.startswith("app") for alias in node.names
        ):
            return True
    return False


def test_no_revision_builds_tables_from_the_live_models():
    revisions = sorted(_VERSIONS.glob("*.py"))
    assert revisions
    for path in revisions:
        tree = ast.parse(path.read_text())
        assert not _calls_create_all(tree), path.name
        assert not _imports_models(tree), path.name


def test_the_check_detects_a_revision_built_from_the_models():
    """The contract above would catch the defect OSPMAE's first revision had."""
    tree = ast.parse(
        "from app.db.session import Base\n"
        "def upgrade():\n"
        "    Base.metadata.create_all(bind=op.get_bind())\n"
    )
    assert _calls_create_all(tree)
    assert _imports_models(tree)
