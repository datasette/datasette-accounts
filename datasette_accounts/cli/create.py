"""``datasette accounts create`` — create a single account."""

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


@accounts.command(name="create")
@click.argument("username", required=False)
@click.option("--admin", "is_admin", is_flag=True, help="Create as an admin.")
@click.option("--password", help="Set the password explicitly (length-checked).")
@click.option(
    "--password-stdin", is_flag=True, help="Read the password from stdin (one line)."
)
@click.option("--generate", is_flag=True, help="Mint a strong random password.")
@click.option(
    "--must-change/--no-must-change",
    default=True,
    help="Force a password change on first login (default: on).",
)
@click.option("--json", "as_json", is_flag=True, help="Machine-readable output.")
@_interactive_option
@_yes_option
@_db_options
def create(
    username,
    is_admin,
    password,
    password_stdin,
    generate,
    must_change,
    as_json,
    interactive,
    yes,
    internal,
    metadata,
    actor,
):
    """Create a single account."""

    async def go():
        ds, db_ = await _open_internal(internal, metadata)
        name = username
        admin = is_admin
        change = must_change
        if interactive:
            if not name:
                name = click.prompt("Username")
            admin = click.confirm("Create as an admin?", default=is_admin)
            change = click.confirm(
                "Force a password change on first login?", default=must_change
            )
        elif not name:
            raise click.ClickException("Missing argument 'USERNAME'.")

        # Pre-check to avoid the expensive hash + a stderr line from the write
        # thread on the common duplicate case; create_user re-checks atomically.
        if await db.get_user_by_username(db_, name) is not None:
            raise click.ClickException("Username already taken")
        provided = _read_password(password, password_stdin)
        plaintext, generated = _resolve_password_interactive(
            ds, provided, generate, interactive
        )

        _confirm(f"Create {'admin' if admin else 'user'} account {name!r}?", yes)
        try:
            user_id = await db.create_user(
                db_,
                _actor_id(actor),
                name,
                hash_password(plaintext),
                admin,
                change,
            )
        except db.UsernameTakenError:
            raise click.ClickException("Username already taken")
        result = {"ok": True, "id": user_id, "username": name}
        if generated:
            result["password"] = plaintext

        def human():
            click.echo(f"Created {name} ({'admin' if admin else 'user'}).")
            if generated:
                click.echo(f"Password (shown once): {plaintext}")

        _emit(result, as_json, human)

    _run(go())
