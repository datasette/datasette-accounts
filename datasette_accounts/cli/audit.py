"""``datasette accounts audit`` — show the admin-audit trail."""

import click

from .. import db
from .base import (
    _db_options,
    _emit,
    _open_internal,
    _require_user,
    _run,
    _table,
    accounts,
)


@accounts.command(name="audit")
@click.option("--user", "username", help="Filter to one target username.")
@click.option("--operation", "operation", help="Filter to one operation name.")
@click.option("--limit", type=int, default=200, help="Max rows (clamped).")
@click.option("--json", "as_json", is_flag=True, help="Machine-readable output.")
@_db_options
def audit(username, operation, limit, as_json, internal, metadata, actor):
    """Show the admin-audit trail (newest first)."""

    async def go():
        _, db_ = await _open_internal(internal, metadata)
        target_id = None
        if username:
            target_id = (await _require_user(db_, username))["id"]
        rows = await db.list_admin_audit(db_, target_id, operation, limit)

        def human():
            view = [
                {
                    "timestamp": r["timestamp"],
                    "operation": r["operation"],
                    "actor": r["actor_id"] or "",
                    "target": r["target_username"] or r["target_id"] or "",
                    "detail": r["detail"] or "",
                }
                for r in rows
            ]
            click.echo(
                _table(view, ["timestamp", "operation", "actor", "target", "detail"])
            )

        _emit({"ok": True, "audit": rows}, as_json, human)

    _run(go())
