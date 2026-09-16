"""``datasette accounts disable-provider`` — turn a sign-in provider off."""

import click

from .. import db
from ..providers import REGISTRY_ATTR, usable_provider_keys
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

    Every live session that provider minted is revoked in the same step, so
    sign-ins through it end with the switch — except admin accounts' sessions,
    which are kept (there is no acting web session to spare from the shell,
    and an operator turning a provider off shouldn't lock the admins out). The
    prompt says how many sessions will go. Enforces the last-provider guard
    like the admin UI: disabling the final usable provider is refused (recover
    with enable-provider). Effective on the next request. Audited like the
    admin UI toggle.
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
        revoking = await db.count_sessions_for_provider(
            db_, key, keep_admin_sessions=True
        )
        noun = "session" if revoking == 1 else "sessions"
        _confirm(
            f"Disable sign-in provider {key!r}? This signs out {revoking} "
            f"{noun} that signed in through it (admin accounts' sessions are "
            "kept).",
            yes,
        )
        try:
            await db.set_provider_enabled(
                db_,
                _actor_id(actor),
                key,
                False,
                installed_keys=await usable_provider_keys(ds),
                keep_admin_sessions=True,
            )
        except db.LastProviderError:
            raise click.ClickException("Cannot disable the last sign-in provider.")
        _emit(
            {
                "ok": True,
                "enabled": False,
                "changed": True,
                "sessions_revoked": revoking,
            },
            as_json,
            lambda: click.echo(
                f"Disabled {key}. Signed out {revoking} {noun} (admin sessions kept)."
            ),
        )

    _run(go())
