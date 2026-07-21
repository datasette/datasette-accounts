"""``datasette accounts disable-provider`` — turn a sign-in provider off."""

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


@accounts.command(name="disable-provider")
@click.argument("key")
@click.option("--json", "as_json", is_flag=True, help="Machine-readable output.")
@_yes_option
@_db_options
def disable_provider(key, as_json, yes, internal, metadata, actor):
    """Disable a sign-in provider (its entire URL surface goes dead).

    Enforces the last-provider guard like the admin UI: disabling the final
    enabled provider is refused (recover with enable-provider). Effective on the
    next request. Audited like the admin UI toggle.
    """

    async def go():
        ds, db_ = await _open_internal(internal, metadata)
        registry = getattr(ds, REGISTRY_ATTR, {})
        if key not in registry:
            raise click.ClickException(f"no such provider: {key}")
        if not await db.get_provider_enabled(db_, key):
            _emit(
                {"ok": True, "enabled": False, "changed": False},
                as_json,
                lambda: click.echo(f"{key} is already disabled — no change."),
            )
            return
        _confirm(f"Disable sign-in provider {key!r}?", yes)
        try:
            await db.set_provider_enabled(
                db_, _actor_id(actor), key, False, installed_keys=list(registry)
            )
        except db.LastProviderError:
            raise click.ClickException("Cannot disable the last sign-in provider.")
        _emit(
            {"ok": True, "enabled": False, "changed": True},
            as_json,
            lambda: click.echo(f"Disabled {key}."),
        )

    _run(go())
