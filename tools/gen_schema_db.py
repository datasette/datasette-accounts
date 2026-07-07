"""Materialise the internal-DB schema into a fresh SQLite file for codegen.

``solite codegen --schema <db>`` needs a database whose columns + nullability
reflect the *post-migration* state so it can type query results. Rather than
keep a second copy of the DDL, we apply the real migrations from
``datasette_accounts/internal_migrations.py``.

Circular-import gotcha: importing ``datasette_accounts.internal_migrations``
runs the package ``__init__``, which loads Datasette plugin entry points (incl.
the ``datasette-paper`` dev dependency) and can abort on an unrelated import
cycle. ``internal_migrations.py`` has no intra-package imports, so we load it
directly by file path and skip the package ``__init__`` entirely.

Usage: python tools/gen_schema_db.py <output.db>
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

from sqlite_utils import Database

REPO_ROOT = Path(__file__).resolve().parent.parent
MIGRATIONS_PATH = REPO_ROOT / "datasette_accounts" / "internal_migrations.py"


def load_migrations():
    spec = importlib.util.spec_from_file_location(
        "_accounts_internal_migrations", MIGRATIONS_PATH
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.internal_migrations


def main() -> int:
    if len(sys.argv) != 2:
        print(f"usage: {sys.argv[0]} <output.db>", file=sys.stderr)
        return 1
    db = Database(sys.argv[1])
    load_migrations().apply(db)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
