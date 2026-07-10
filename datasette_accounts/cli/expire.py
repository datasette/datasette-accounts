"""``datasette accounts expire`` — set, extend, or clear an account's expiry."""

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


@accounts.command(name="expire")
@click.argument("username")
@click.option(
    "--at",
    metavar="TIMESTAMP",
    help="Expiry deadline as an ISO-8601 timestamp, parsed by SQLite — bare "
    "dates (2027-01-31), Z-suffixed and ±HH:MM offset forms all work "
    "(offsets are converted to UTC). Must be in the future.",
)
@click.option(
    "--in-days",
    type=int,
    metavar="N",
    help="Expiry deadline N days from now (computed in SQL).",
)
@click.option("--clear", is_flag=True, help="Remove the expiry (never expires).")
@click.option("--json", "as_json", is_flag=True, help="Machine-readable output.")
@_yes_option
@_db_options
def expire(username, at, in_days, clear, as_json, yes, internal, metadata, actor):
    """Set, extend, or clear an account's expiry deadline.

    Past the deadline the account behaves like a disabled one — login refused,
    live sessions dead on the next request — but nothing is deleted, and the
    deadline can be extended or cleared at any time. Exactly one of --at /
    --in-days / --clear is required. All timestamp parsing, UTC conversion,
    and relative math happen in SQLite; the CLI passes values through
    verbatim.
    """
    given = [
        flag
        for flag, value in (
            ("--at", at),
            ("--in-days", in_days),
            ("--clear", clear or None),
        )
        if value is not None
    ]
    if len(given) != 1:
        raise click.UsageError("Pass exactly one of --at / --in-days / --clear.")

    async def go():
        _, db_ = await _open_internal(internal, metadata)
        user = await _require_user(db_, username)
        if clear:
            summary = f"Clear the expiry for {username!r}?"
        elif at is not None:
            summary = f"Set {username!r} to expire at {at}?"
        else:
            summary = f"Set {username!r} to expire {in_days} days from now?"
        _confirm(summary, yes)
        try:
            # --clear passes both as None, which clears the column.
            stored = await db.set_user_expiry(
                db_, _actor_id(actor), user["id"], at=at, in_days=in_days
            )
        except db.InvalidExpiryError:
            raise click.ClickException("Expiry must be a valid timestamp in the future")
        except db.LastAdminError:
            raise click.ClickException("Cannot set an expiry on the last admin")
        if stored is False:
            # _require_user just resolved the account, but a concurrent delete
            # can still lose the race — never report a write that didn't land.
            raise click.ClickException(f"no such user: {username}")

        def human():
            if stored is None:
                click.echo(f"Cleared expiry for {username}.")
            else:
                click.echo(f"{username} expires at {stored}.")

        _emit({"ok": True, "expires_at": stored}, as_json, human)

    _run(go())
