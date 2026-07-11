"""``datasette accounts registration`` — the runtime self-registration toggle."""

import click

from .. import db
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


@accounts.command(name="registration")
@click.argument(
    "state",
    type=click.Choice(["on", "off", "status"]),
    default="status",
    required=False,
)
@click.option("--json", "as_json", is_flag=True, help="Machine-readable output.")
@_yes_option
@_db_options
def registration(state, as_json, yes, internal, metadata, actor):
    """Open, close, or inspect self-registration (default: status).

    A documented alias for the password provider's signups policy (decision
    D5): ``on`` == ``set-signups password approval``, ``off`` == ``set-signups
    password off``. Kept because scripts reference it. The same audited runtime
    setting in the internal DB, effective on the next request, no restart. While
    on, anyone can request an account at /-/register; requests land in the
    pending-approval queue (see approve / reject).
    """

    async def go():
        _, db_ = await _open_internal(internal, metadata)
        current = await db.get_registration_enabled(db_)

        if state == "status":
            _emit(
                {"ok": True, "enabled": current},
                as_json,
                lambda: click.echo(
                    f"Self-registration is {'on' if current else 'off'}."
                ),
            )
            return

        target = state == "on"
        if current == target:
            # A no-op needs no confirmation (it returns before the mutation)
            # and writes no audit row (set_registration_enabled would no-op
            # anyway; skipping here keeps the output honest).
            _emit(
                {"ok": True, "enabled": current},
                as_json,
                lambda: click.echo(
                    f"Self-registration is already {state} — no change."
                ),
            )
            return

        if target:
            summary = (
                "Enable self-registration? /-/register becomes publicly "
                "reachable and anyone can request an account."
            )
        else:
            summary = "Disable self-registration?"
        _confirm(summary, yes)
        enabled = await db.set_registration_enabled(db_, _actor_id(actor), target)

        def human():
            click.echo(f"{'Enabled' if enabled else 'Disabled'} self-registration.")
            click.echo(
                "Tip: this is an alias for "
                f"'accounts set-signups password {'approval' if enabled else 'off'}'."
            )

        _emit({"ok": True, "enabled": enabled}, as_json, human)

    _run(go())
