"""``datasette accounts bootstrap-admin`` — create the first admin, idempotently."""

import click

from .. import db
from ..passwords import hash_password
from .base import (
    _actor_id,
    _confirm,
    _db_options,
    _emit,
    _interactive_option,
    _open_internal,
    _read_password,
    _resolve_password_interactive,
    _run,
    _yes_option,
    accounts,
)


@accounts.command(name="bootstrap-admin")
@click.argument("username", required=False)
@click.option("--password", help="Set the password explicitly.")
@click.option("--password-stdin", is_flag=True, help="Read the password from stdin.")
@click.option("--generate", is_flag=True, help="Mint a strong random password.")
@click.option(
    "--must-change/--no-must-change",
    default=False,
    help="Force a password change on first login (default: off here).",
)
@click.option(
    "--force", is_flag=True, help="Create even if an enabled admin already exists."
)
@click.option("--json", "as_json", is_flag=True, help="Machine-readable output.")
@_interactive_option
@_yes_option
@_db_options
def bootstrap_admin(
    username,
    password,
    password_stdin,
    generate,
    must_change,
    force,
    as_json,
    interactive,
    yes,
    internal,
    metadata,
    actor,
):
    """Create the first admin — idempotent, safe to run on every container boot."""

    async def go():
        ds, db_ = await _open_internal(internal, metadata)
        if not force and await db.count_enabled_admins(db_) > 0:
            _emit(
                {"ok": True, "skipped": True},
                as_json,
                lambda: click.echo("admin already exists — skipping"),
            )
            return
        name = username
        if interactive and not name:
            name = click.prompt("Username")
        elif not name:
            raise click.ClickException("Missing argument 'USERNAME'.")

        if await db.get_user_by_username(db_, name) is not None:
            raise click.ClickException("Username already taken")
        provided = _read_password(password, password_stdin)
        plaintext, generated = _resolve_password_interactive(
            ds, provided, generate, interactive
        )

        _confirm(f"Create the first admin account {name!r}?", yes)
        try:
            user_id = await db.create_user(
                db_,
                _actor_id(actor),
                name,
                hash_password(plaintext),
                True,
                must_change,
            )
        except db.UsernameTakenError:
            raise click.ClickException("Username already taken")
        result = {"ok": True, "id": user_id, "username": name}
        if generated:
            result["password"] = plaintext

        def human():
            click.echo(f"Created admin {name}.")
            if generated:
                click.echo(f"Password (shown once): {plaintext}")

        _emit(result, as_json, human)

    _run(go())
