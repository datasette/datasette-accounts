"""``datasette accounts list`` — list accounts, with optional filters."""

import click

from .. import db
from .base import _db_options, _emit, _open_internal, _run, _table, accounts


@accounts.command(name="list")
@click.option("--admins", is_flag=True, help="Only admins.")
@click.option("--pending", is_flag=True, help="Only never-signed-in accounts.")
@click.option("--locked", is_flag=True, help="Only currently locked-out accounts.")
@click.option("--disabled", is_flag=True, help="Only disabled accounts.")
@click.option("--expired", is_flag=True, help="Only expired accounts.")
@click.option("--json", "as_json", is_flag=True, help="Machine-readable output.")
@_db_options
def list_users(
    admins, pending, locked, disabled, expired, as_json, internal, metadata, actor
):
    """List accounts."""

    async def go():
        _, db_ = await _open_internal(internal, metadata)
        rows = [db.to_user_row(r) for r in await db.list_users(db_)]
        if admins:
            rows = [r for r in rows if r["is_admin"]]
        if pending:
            rows = [r for r in rows if r["last_login_at"] is None]
        if locked:
            rows = [r for r in rows if r["locked"]]
        if disabled:
            rows = [r for r in rows if r["disabled"]]
        if expired:
            rows = [r for r in rows if r["expired"]]

        def human():
            view = [
                {
                    "username": r["username"],
                    "admin": "yes" if r["is_admin"] else "",
                    "disabled": "yes" if r["disabled"] else "",
                    "locked": "yes" if r["locked"] else "",
                    "pending": "yes" if r["last_login_at"] is None else "",
                    "last_login": r["last_login_at"] or "",
                    "expires": r["expires_at"] or "",
                }
                for r in rows
            ]
            click.echo(
                _table(
                    view,
                    [
                        "username",
                        "admin",
                        "disabled",
                        "locked",
                        "pending",
                        "last_login",
                        "expires",
                    ],
                )
            )

        _emit({"ok": True, "users": rows}, as_json, human)

    _run(go())
