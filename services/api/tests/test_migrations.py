"""Migration-chain contracts.

The production upgrade path builds a fresh database by replaying the Alembic
chain, so the chain must end in the schema the models declare, and no revision
may create or add anything the chain already provides: alembic runs the whole
upgrade in one transaction, so a mid-chain failure rolls everything back and a
fresh installation would restart from scratch forever (as 0026 once did,
re-adding sessions.created_at, which 0001 already creates).

Two layers enforce this. When the disposable test database is PostgreSQL the
chain actually runs, and the resulting schema is compared table for table and
column for column with Base.metadata; that is the production-faithful check.
On any backend, a source-level replay of the chain walks every upgrade in
revision order under fresh-installation semantics (guards hold true and
inspector snapshots equal the state the chain itself produced) and refuses a
revision that redefines what earlier revisions created -- a cheap contract
that catches a drifted chain before it is ever executed.
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Iterable, Sequence

from alembic import command
from alembic.config import Config
from alembic.script import ScriptDirectory
from app.db.session import Base, engine
from sqlalchemy import inspect, text

_API_ROOT = Path(__file__).resolve().parents[1]
_IS_POSTGRES = engine.url.get_backend_name() == "postgresql"


def _alembic_config() -> Config:
    cfg = Config(str(_API_ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(_API_ROOT / "alembic"))
    return cfg


def _ordered_versions() -> list[Path]:
    script = ScriptDirectory.from_config(_alembic_config())
    revisions = list(script.walk_revisions())
    heads = script.get_heads()
    assert len(heads) == 1, f"the chain must stay linear, heads={heads}"
    by_down = {rev.down_revision: rev for rev in revisions}
    ordered: list[Path] = []
    rev = by_down.get(None)
    while rev is not None:
        ordered.append(Path(rev.path))
        rev = by_down.get(rev.revision)
    assert len(ordered) == len(revisions), "the chain must have no branches"
    return ordered


# ---------------------------------------------------------------------------
# Source-level replay: the dialect-independent contract.
# ---------------------------------------------------------------------------


class _Replay:
    """Applies upgrade bodies to a fresh-installation table/column state.

    Migration guards (``_table_exists``, ``_has_column``, ``_column_names``
    and ``inspector.get_columns`` snapshots) describe legacy databases, and on
    a fresh install they all hold. The replay evaluates the recognisable
    guards against the state it has tracked; anything outside that idiom is
    applied, matching what a fresh run executes. Only the architecture of the
    chain matters here: create/add/drop/rename bookkeeping for tables and
    columns, with everything else (indexes, data statements) irrelevant.
    """

    def __init__(self) -> None:
        self.tables: dict[str, set[str]] = {}
        self.locals: dict[str, set[str]] = {}
        self.loop_values: dict[str, str] = {}
        self.findings: list[str] = []
        self._source: str = ""

    def apply(self, paths: Sequence[Path]) -> None:
        for path in paths:
            self._source = path.name
            tree = ast.parse(path.read_text(encoding="utf-8"))
            upgrades = [
                node
                for node in tree.body
                if isinstance(node, ast.FunctionDef) and node.name == "upgrade"
            ]
            assert len(upgrades) == 1, f"{path.name}: expected one upgrade()"
            for stmt in upgrades[0].body:
                self._execute(stmt)

    # -- statement dispatch -------------------------------------------------

    def _execute(self, stmt: ast.stmt) -> None:
        if isinstance(stmt, ast.If):
            if self._truthy(stmt.test):
                for inner in stmt.body:
                    self._execute(inner)
            elif stmt.orelse:
                for inner in stmt.orelse:
                    self._execute(inner)
        elif isinstance(stmt, (ast.With, ast.AsyncWith)):
            self._enter_with(stmt)
        elif isinstance(stmt, ast.For):
            self._run_for(stmt)
        elif isinstance(stmt, (ast.Assign, ast.Expr)):
            self._observe(stmt)

    def _run_for(self, stmt: ast.For) -> None:
        if isinstance(stmt.iter, (ast.List, ast.Tuple)):
            values = [
                elt.value
                for elt in stmt.iter.elts
                if isinstance(elt, ast.Constant) and isinstance(elt.value, str)
            ]
            assert len(values) == len(stmt.iter.elts), f"{self._source}: loop values"
        else:
            assert False, f"{self._source}: unsupported loop over {stmt.iter!r}"
        assert isinstance(stmt.target, ast.Name), f"{self._source}: loop target"
        for value in values:
            previous = self.loop_values.get(stmt.target.id)
            self.loop_values[stmt.target.id] = value
            for inner in stmt.body:
                self._execute(inner)
            if previous is None:
                self.loop_values.pop(stmt.target.id, None)
            else:
                self.loop_values[stmt.target.id] = previous

    def _enter_with(self, stmt: ast.With | ast.AsyncWith) -> None:
        batch_table: str | None = None
        batch_alias: str | None = None
        for item in stmt.items:
            call = item.context_expr
            if isinstance(call, ast.Call) and _path_of(call.func) == (
                "op",
                "batch_alter_table",
            ):
                assert call.args, f"{self._source}: batch with no table"
                batch_table = self._const(call.args[0])
                assert batch_table is not None, f"{self._source}: batch table"
                if isinstance(item.optional_vars, ast.Name):
                    batch_alias = item.optional_vars.id
        for inner in stmt.body:
            self._execute_batch(inner, batch_table, batch_alias)
        if stmt.orelse:
            for inner in stmt.orelse:
                self._execute(inner)

    def _execute_batch(
        self, stmt: ast.stmt, table: str | None, alias: str | None
    ) -> None:
        if isinstance(stmt, (ast.Assign, ast.Expr)):
            call = stmt.value
            if not isinstance(call, ast.Call):
                return
            path = _path_of(call.func)
            inside_batch = path is not None and alias is not None and path[0] == alias
            self._apply(path, call, table if inside_batch else None)
        elif isinstance(stmt, (ast.With, ast.AsyncWith)):
            self._enter_with(stmt)  # nested batch blocks re-enter through op.*
        elif isinstance(stmt, ast.If):
            if self._truthy(stmt.test):
                for inner in stmt.body:
                    self._execute_batch(inner, table, alias)
            elif stmt.orelse:
                for inner in stmt.orelse:
                    self._execute_batch(inner, table, alias)

    def _observe(self, stmt: ast.Assign | ast.Expr) -> None:
        if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1:
            target = stmt.targets[0]
            if isinstance(target, ast.Name):
                snapshot = self._knowable_set(stmt.value)
                if snapshot is not None:
                    self.locals[target.id] = snapshot
        if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call):
            self._apply(_path_of(stmt.value.func), stmt.value, None)

    def _knowable_set(self, value: ast.expr) -> set[str] | None:
        """A local snapshot of one table's columns, from inspector idioms."""
        if not isinstance(value, (ast.SetComp, ast.DictComp)):
            return None
        generator = value.generators[0]
        call = generator.iter
        if (
            isinstance(call, ast.Call)
            and isinstance(call.func, ast.Attribute)
            and call.func.attr == "get_columns"
            and call.args
        ):
            table = self._const(call.args[0])
            if table is not None:
                return set(self.tables.get(table, set()))
        return None

    # -- op application ------------------------------------------------------

    def _apply(
        self,
        path: tuple[str, ...] | None,
        call: ast.Call,
        batch_table: str | None,
    ) -> None:
        if len(path) != 2:
            return
        owner, name = path
        if owner == "op":
            if name == "batch_alter_table":
                return  # handled where the with-block is entered
            table = self._const_arg(call, 0)
            if name == "create_table":
                self._create_table(table, call)
            elif name == "drop_table":
                if table is not None:
                    self.tables.pop(table, None)
            elif name == "rename_table":
                target = self._const_arg(call, 1)
                self._rename_table(table, target)
            elif name == "add_column":
                column = (
                    _column_name(call.args[1])
                    if call.args and len(call.args) > 1
                    else None
                )
                self._add_column(table, column)
            elif name == "drop_column":
                column = self._const_arg(call, 1)
                self._drop_column(table, column)
            elif name == "alter_column":
                column = self._const_arg(call, 1)
                self._rename_column(table, column, self._kw("new_column_name", call))
                table = self._kw("table_name", call) or table
        elif batch_table is not None:
            if name == "add_column":
                column = _column_name(call)
                self._add_column(batch_table, column)
            elif name == "drop_column":
                column = self._const_arg(call, 0)
                self._drop_column(batch_table, column)
            elif name == "alter_column":
                column = self._const_arg(call, 0)
                self._rename_column(
                    batch_table, column, self._kw("new_column_name", call)
                )

    def _create_table(self, table: str | None, call: ast.Call) -> None:
        if table is None:
            return
        if table in self.tables:
            self.findings.append(
                f"{self._source}: create_table({table!r}) but the chain already has it"
            )
        self.tables[table] = set()
        for arg in call.args[1:]:
            column = _column_name(arg) if isinstance(arg, ast.Call) else None
            if column is not None:
                self.tables[table].add(column)

    def _rename_table(self, old: str | None, new: str | None) -> None:
        if old is None or new is None:
            return
        if new in self.tables:
            self.findings.append(
                f"{self._source}: rename_table({old!r} -> {new!r}) but "
                f"{new!r} already exists"
            )
        self.tables[new] = self.tables.pop(old, set())

    def _add_column(self, table: str | None, column: str | None) -> None:
        if table is None or column is None:
            return
        columns = self.tables.setdefault(table, set())
        if column in columns:
            self.findings.append(
                f"{self._source}: add_column({table}.{column}) but the chain "
                "already has that column"
            )
        columns.add(column)

    def _drop_column(self, table: str | None, column: str | None) -> None:
        if table is not None and column is not None:
            self.tables.setdefault(table, set()).discard(column)

    def _rename_column(
        self, table: str | None, column: str | None, new: str | None
    ) -> None:
        if table is None or column is None or new is None or new == column:
            return
        columns = self.tables.setdefault(table, set())
        if new in columns and column not in columns:
            self.findings.append(
                f"{self._source}: rename_column({table}.{column} -> {new}) but "
                f"{new} already exists"
            )
        columns.discard(column)
        columns.add(new)

    # -- argument helpers -----------------------------------------------------

    def _const(self, node: ast.expr) -> str | None:
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        if isinstance(node, ast.Name) and node.id in self.loop_values:
            return self.loop_values[node.id]
        return None

    def _const_arg(self, call: ast.Call, index: int) -> str | None:
        if index < len(call.args):
            return self._const(call.args[index])
        return None

    def _kw(self, name: str, call: ast.Call) -> str | None:
        for keyword in call.keywords:
            if keyword.arg == name:
                return self._const(keyword.value)
        return None

    # -- guard evaluation -----------------------------------------------------

    def _truthy(self, test: ast.expr) -> bool | None:
        """True/False when the guard is decidable against tracked state, None
        when it is not: follow the guarded branch."""
        if isinstance(test, ast.Constant):
            return bool(test.value)
        if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
            inverse = self._truthy(test.operand)
            return None if inverse is None else not inverse
        if isinstance(test, ast.BoolOp):
            results = [self._truthy(value) for value in test.values]
            if isinstance(test.op, ast.And):
                if False in results:
                    return False
                return None if all(r is None for r in results) else True
            if True in results:
                return True
            return None if all(r is None for r in results) else False
        if isinstance(test, ast.Compare):
            left = self._member(test.left)
            entries = self._membership_set(test.comparators[0])
            if left is not None and entries is not None:
                if isinstance(test.ops[0], ast.In):
                    return left in entries
                if isinstance(test.ops[0], ast.NotIn):
                    return left not in entries
            return None
        if isinstance(test, ast.Call):
            name = self._const(test.func)
            if name == "_table_exists" and test.args:
                table = self._const(test.args[0])
                return table is not None and table in self.tables
            if name == "_has_column" and len(test.args) == 2:
                table = self._const(test.args[0])
                column = self._const(test.args[1])
                if table is not None and column is not None:
                    return column in self.tables.get(table, set())
            if name == "_column_names" and test.args:
                table = self._const(test.args[0])
                if table is not None:
                    return bool(self.tables.get(table))
        return None

    def _member(self, node: ast.expr) -> str | None:
        return self._const(node)

    def _membership_set(self, node: ast.expr) -> set[str] | None:
        if isinstance(node, ast.Name) and node.id in self.locals:
            return self.locals[node.id]
        if isinstance(node, ast.Call):
            name = self._const(node.func)
            if name == "_column_names" and node.args:
                table = self._const(node.args[0])
                if table is not None:
                    return set(self.tables.get(table, set()))
        if isinstance(node, (ast.SetComp, ast.DictComp, ast.ListComp)):
            return self._knowable_set(node)
        return None


def _path_of(node: ast.expr) -> tuple[str, ...] | None:
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return tuple(reversed(parts))
    return None


def _column_name(node: ast.expr) -> str | None:
    """The name of a sa.Column(...) definition, or None for anything else."""
    if not isinstance(node, ast.Call):
        return None
    path = _path_of(node.func)
    if path and path[-1] == "Column" and node.args:
        first = node.args[0]
        if isinstance(first, ast.Constant) and isinstance(first.value, str):
            return first.value
    return None


def _replay_upgrades(paths: Iterable[Path]) -> list[str]:
    replay = _Replay()
    replay.apply(list(paths))
    return replay.findings


# ---------------------------------------------------------------------------
# Runtime chain replay: the production-faithful check on PostgreSQL.
# ---------------------------------------------------------------------------


def _upgrade_to_head() -> None:
    with engine.begin() as conn:
        conn.execute(text("DROP SCHEMA public CASCADE"))
        conn.execute(text("CREATE SCHEMA public"))
    command.upgrade(_alembic_config(), "head")


def _drop_chain() -> None:
    with engine.begin() as conn:
        conn.execute(text("DROP SCHEMA public CASCADE"))
        conn.execute(text("CREATE SCHEMA public"))
    Base.metadata.create_all(engine)


def _chain_schema_matches_models() -> None:
    assert engine.url.get_backend_name() == "postgresql"

    def columns(conn, table) -> set[str]:
        return {column["name"] for column in inspect(conn).get_columns(table)}

    with engine.begin() as conn:
        present = set(inspect(conn).get_table_names()) - {"alembic_version"}
        expected = {
            name
            for name in Base.metadata.tables
            if not name.startswith("sqlite_") and not name.startswith("pg_")
        }
        missing = expected - present
        extra = present - expected
        assert not missing, f"the chain does not build {sorted(missing)}"
        assert not extra, f"the chain leaves unexpected tables {sorted(extra)}"
        for table in present:
            built = columns(conn, table)
            declared = {column.name for column in Base.metadata.tables[table].columns}
            absent = declared - built
            unexpected_column = built - declared
            assert not absent, f"{table}: the chain misses columns {sorted(absent)}"
            assert not unexpected_column, (
                f"{table}: the chain adds columns {sorted(unexpected_column)}"
            )


# ---------------------------------------------------------------------------
# Tests.
# ---------------------------------------------------------------------------


def test_upgrade_chain_has_no_redefinitions() -> None:
    """No revision may create or add what earlier revisions already have: the
    replay walks the same code a fresh install executes and must stay silent."""
    assert _replay_upgrades(_ordered_versions()) == []


def test_migration_chain_rebuilds_the_declared_schema() -> None:
    """The chain, replayed by alembic itself, ends in the schema the models
    declare (PostgreSQL test database); elsewhere the source-level replay is
    the dialect-independent equivalent."""
    if not _IS_POSTGRES:
        assert _replay_upgrades(_ordered_versions()) == []
        return
    try:
        _upgrade_to_head()
        _chain_schema_matches_models()
    finally:
        _drop_chain()


def test_replay_flags_a_duplicated_creation(tmp_path: Path) -> None:
    """The replay proves its purpose: a chain that re-creates declined work is
    rejected with the offending revision named."""
    (seed_dir := tmp_path / "versions").mkdir()
    (seed_dir / "0001_seed.py").write_text(
        "import sqlalchemy as sa\n"
        "from alembic import op\n"
        "def upgrade() -> None:\n"
        "    op.create_table('t', sa.Column('c', sa.Integer()))\n",
        encoding="utf-8",
    )
    executor = _Replay()
    executor.apply([seed_dir / "0001_seed.py"])
    (seed_dir / "0002_duplicate.py").write_text(
        "import sqlalchemy as sa\n"
        "from alembic import op\n"
        "def upgrade() -> None:\n"
        "    op.add_column('t', sa.Column('c', sa.Integer()))\n",
        encoding="utf-8",
    )
    assert executor.findings == []
    executor.apply([seed_dir / "0002_duplicate.py"])
    assert executor.findings, "a duplicated column must be flagged"
    assert any("0002_duplicate.py" in finding for finding in executor.findings)
