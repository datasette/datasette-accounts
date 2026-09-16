"""``datasette accounts providers`` — list installed sign-in providers."""

import click

from .. import db
from ..providers import REGISTRY_ATTR, provider_source
from .base import _db_options, _emit, _open_internal, _run, _table, accounts


@accounts.command(name="providers")
@click.option("--json", "as_json", is_flag=True, help="Machine-readable output.")
@_db_options
def providers(as_json, internal, metadata, actor):
    """List installed sign-in providers + their enabled/signups state.

    Installed providers come from the pluggy hook (the registry built at
    startup); the enabled bit and signups policy come from the runtime settings
    rows. Use enable-provider / disable-provider / set-signups to change them.
    """

    async def go():
        ds, db_ = await _open_internal(internal, metadata)
        registry = getattr(ds, REGISTRY_ATTR, {})
        rows = []
        for key, provider in registry.items():
            rows.append(
                {
                    "key": key,
                    "label": provider.label,
                    "source": provider_source(provider),
                    "enabled": await db.get_provider_enabled(db_, key),
                    "signups": await db.get_provider_signups(db_, key),
                }
            )
        _emit(
            {"ok": True, "providers": rows},
            as_json,
            lambda: click.echo(
                _table(rows, ["key", "label", "source", "enabled", "signups"])
            ),
        )

    _run(go())
