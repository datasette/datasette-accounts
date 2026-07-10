"""``datasette accounts approve`` — approve a pending self-registered account.

Written explicitly rather than via ``_simple_mutation``: approving an account
that isn't awaiting approval should say so (a no-op, like promote/demote's
"no change") instead of claiming an approval happened.
"""

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


@accounts.command(name="approve")
@click.argument("username")
@click.option("--json", "as_json", is_flag=True, help="Machine-readable output.")
@_yes_option
@_db_options
def approve(username, as_json, yes, internal, metadata, actor):
    """Approve a self-registered account awaiting approval.

    The account can sign in immediately afterwards with the password it chose
    at registration. Approving an account that isn't awaiting approval is a
    no-op.
    """

    async def go():
        _, db_ = await _open_internal(internal, metadata)
        user = await _require_user(db_, username)
        if not user["pending_approval"]:
            # A no-op needs no confirmation (it returns before the mutation).
            _emit(
                {"ok": True, "changed": False},
                as_json,
                lambda: click.echo(f"{username} is not awaiting approval — no change."),
            )
            return
        _confirm(f"Approve the account request from {username!r}?", yes)
        if not await db.approve_user(db_, _actor_id(actor), user["id"]):
            # _require_user just resolved the account, but a concurrent delete
            # can still lose the race — never report a write that didn't land.
            raise click.ClickException(f"no such user: {username}")
        _emit(
            {"ok": True, "changed": True},
            as_json,
            lambda: click.echo(f"Approved {username}."),
        )

    _run(go())
