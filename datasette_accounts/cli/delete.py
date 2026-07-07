"""``datasette accounts delete`` — delete a user (last-admin guarded)."""

import click

from .. import db
from .base import (
    _actor_id,
    _confirm,
    _db_options,
    _emit,
    _open_internal,
    _require_user,
    _run,
    _yes_option,
    accounts,
)


@accounts.command(name="delete")
@click.argument("username")
@click.option("--json", "as_json", is_flag=True, help="Machine-readable output.")
@_yes_option
@_db_options
def delete(username, as_json, yes, internal, metadata, actor):
    """Delete a user (last-admin guarded)."""

    async def go():
        _, db_ = await _open_internal(internal, metadata)
        user = await _require_user(db_, username)
        _confirm(f"Delete account {username!r}? This cannot be undone.", yes)
        try:
            await db.delete_user(db_, _actor_id(actor), user["id"])
        except db.LastAdminError:
            raise click.ClickException("Cannot delete the last admin")
        _emit(
            {"ok": True},
            as_json,
            lambda: click.echo(f"Deleted {username}."),
        )

    _run(go())
