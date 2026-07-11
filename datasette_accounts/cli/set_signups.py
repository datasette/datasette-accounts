"""``datasette accounts set-signups`` — a provider's signups policy."""

import click

from .. import db
from ..providers import REGISTRY_ATTR
from .base import (
    _actor_id,
    _confirm,
    _db_options,
    _emit,
    _open_internal,
    _run,
    _yes_option,
    accounts,
)


@accounts.command(name="set-signups")
@click.argument("key")
@click.argument("mode", type=click.Choice(["off", "approval", "auto"]))
@click.option("--json", "as_json", is_flag=True, help="Machine-readable output.")
@_yes_option
@_db_options
def set_signups(key, mode, as_json, yes, internal, metadata, actor):
    """Set a provider's signups policy: off | approval | auto.

    off — unmatched identities are refused. approval — provision a pending
    account into the approval queue. auto — provision an active account and sign
    in (trusted IdPs only). Effective on the next request; audited.
    """

    async def go():
        ds, db_ = await _open_internal(internal, metadata)
        registry = getattr(ds, REGISTRY_ATTR, {})
        if key not in registry:
            raise click.ClickException(f"no such provider: {key}")
        current = await db.get_provider_signups(db_, key)
        if current == mode:
            _emit(
                {"ok": True, "signups": mode, "changed": False},
                as_json,
                lambda: click.echo(f"{key} signups already {mode} — no change."),
            )
            return
        _confirm(f"Set {key!r} signups to {mode}?", yes)
        await db.set_provider_signups(db_, _actor_id(actor), key, mode)
        _emit(
            {"ok": True, "signups": mode, "changed": True},
            as_json,
            lambda: click.echo(f"Set {key} signups to {mode}."),
        )

    _run(go())
