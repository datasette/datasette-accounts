"""``datasette accounts enable-provider`` — the break-glass sign-in recovery.

This is decision D9's break-glass: it works with only disk access (no web auth),
so an operator who disabled password and then lost the sole external IdP can
always restore a working sign-in path from the shell.
"""

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


@accounts.command(name="enable-provider")
@click.argument("key")
@click.option("--json", "as_json", is_flag=True, help="Machine-readable output.")
@_yes_option
@_db_options
def enable_provider(key, as_json, yes, internal, metadata, actor):
    """Enable a sign-in provider (break-glass — works with only disk access).

    The recovery when an admin disables password and the sole external IdP then
    breaks: `enable-provider password` restores password login with no web
    session, effective on the next request. Audited like the admin UI toggle.
    """

    async def go():
        ds, db_ = await _open_internal(internal, metadata)
        registry = getattr(ds, REGISTRY_ATTR, {})
        if key not in registry:
            raise click.ClickException(f"no such provider: {key}")
        if await db.get_provider_enabled(db_, key):
            _emit(
                {"ok": True, "enabled": True, "changed": False},
                as_json,
                lambda: click.echo(f"{key} is already enabled — no change."),
            )
            return
        _confirm(f"Enable sign-in provider {key!r}?", yes)
        await db.set_provider_enabled(
            db_, _actor_id(actor), key, True, installed_keys=list(registry)
        )
        _emit(
            {"ok": True, "enabled": True, "changed": True},
            as_json,
            lambda: click.echo(f"Enabled {key}."),
        )

    _run(go())
