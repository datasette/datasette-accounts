"""``datasette accounts reject`` — reject (delete) a pending account request.

Written explicitly rather than via ``_simple_mutation``: reject must refuse
non-pending targets (a mis-aimed reject can never delete an active user —
that's ``delete``'s job) and its confirmation spells out that it deletes.
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


@accounts.command(name="reject")
@click.argument("username")
@click.option("--json", "as_json", is_flag=True, help="Machine-readable output.")
@_yes_option
@_db_options
def reject(username, as_json, yes, internal, metadata, actor):
    """Reject a self-registered account awaiting approval.

    Rejecting DELETES the pending account row (the username is preserved in
    the audit detail). Refuses accounts that aren't awaiting approval, so a
    mis-aimed reject can never delete an active user — use delete for those.
    """

    async def go():
        _, db_ = await _open_internal(internal, metadata)
        user = await _require_user(db_, username)
        if not user["pending_approval"]:
            # Fail fast, before the confirmation prompt; reject_user re-checks
            # inside its transaction anyway (the except below covers the race).
            raise click.ClickException("Account is not awaiting approval")
        _confirm(
            f"Reject and DELETE the account request from {username!r}? "
            "This cannot be undone.",
            yes,
        )
        try:
            rejected = await db.reject_user(db_, _actor_id(actor), user["id"])
        except db.NotPendingError:
            raise click.ClickException("Account is not awaiting approval")
        if not rejected:
            raise click.ClickException(f"no such user: {username}")
        _emit(
            {"ok": True},
            as_json,
            lambda: click.echo(
                f"Rejected {username} — the account request is deleted."
            ),
        )

    _run(go())
