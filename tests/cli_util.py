"""Shared helpers for the ``test_cli_*`` modules.

Not collected by pytest (the filename doesn't match ``test_*``); imported by the
per-command test modules. Mutations prompt "are you sure?" unless ``-y/--yes`` is
passed, so the non-interactive helpers here pass ``-y``.
"""

import sqlite3

# Import Datasette before the plugin submodules so entry points load fully.
from datasette.app import Datasette  # noqa: F401

from click.testing import CliRunner

from datasette_accounts.cli import accounts


def run(*args, input=None):
    """Invoke the ``accounts`` group with CliRunner (exceptions not swallowed)."""
    return CliRunner().invoke(accounts, list(args), input=input, catch_exceptions=False)


def query(db_path, sql, params=()):
    """Run a read query against the temp internal DB and return dict rows."""
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        return [dict(r) for r in conn.execute(sql, params).fetchall()]
    finally:
        conn.close()


def make_admin(db_path, username="admin", password="adminpass123"):
    """Create the first admin non-interactively (``-y`` bypasses the prompt)."""
    return run("bootstrap-admin", username, "--password", password, "-y", "-i", db_path)
