"""``datasette accounts login-attempts`` — show the login-attempt audit."""

import click

from .. import db
from .base import _db_options, _emit, _open_internal, _run, _table, accounts


@accounts.command(name="login-attempts")
@click.option("--user", "username", help="Filter to one username.")
@click.option("--ip", help="Filter to one IP.")
@click.option("--failed", is_flag=True, help="Only failed attempts (success = 0).")
@click.option("--limit", type=int, default=200, help="Max rows (clamped).")
@click.option("--json", "as_json", is_flag=True, help="Machine-readable output.")
@_db_options
def login_attempts(username, ip, failed, limit, as_json, internal, metadata, actor):
    """Show the login-attempt audit (newest first)."""

    async def go():
        _, db_ = await _open_internal(internal, metadata)
        rows = await db.list_login_attempts(db_, username or None, ip or None, limit)
        if failed:
            rows = [r for r in rows if not r["success"]]

        def human():
            view = [
                {
                    "timestamp": r["timestamp"],
                    "username": r["username"] or "",
                    "ip": r["ip"] or "",
                    "success": "yes" if r["success"] else "",
                    "reason": r["reason"] or "",
                }
                for r in rows
            ]
            click.echo(
                _table(view, ["timestamp", "username", "ip", "success", "reason"])
            )

        _emit({"ok": True, "attempts": rows}, as_json, human)

    _run(go())
