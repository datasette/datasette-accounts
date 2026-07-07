"""``datasette accounts reset-password`` — reset a user's password."""

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
    _require_user,
    _resolve_password_interactive,
    _run,
    _yes_option,
    accounts,
)


@accounts.command(name="reset-password")
@click.argument("username")
@click.option("--password", help="Set the password explicitly.")
@click.option("--password-stdin", is_flag=True, help="Read the password from stdin.")
@click.option("--generate", is_flag=True, help="Mint a strong random password.")
@click.option("--json", "as_json", is_flag=True, help="Machine-readable output.")
@_interactive_option
@_yes_option
@_db_options
def reset_password(
    username,
    password,
    password_stdin,
    generate,
    as_json,
    interactive,
    yes,
    internal,
    metadata,
    actor,
):
    """Reset a user's password (forces a change on next login + revokes sessions)."""

    async def go():
        ds, db_ = await _open_internal(internal, metadata)
        user = await _require_user(db_, username)
        provided = _read_password(password, password_stdin)
        plaintext, generated = _resolve_password_interactive(
            ds, provided, generate, interactive
        )
        _confirm(
            f"Reset the password for {username!r}? This revokes their sessions.",
            yes,
        )
        await db.reset_password(
            db_, _actor_id(actor), user["id"], hash_password(plaintext)
        )
        result = {"ok": True, "username": username}
        if generated:
            result["password"] = plaintext

        def human():
            click.echo(f"Reset password for {username}.")
            if generated:
                click.echo(f"Password (shown once): {plaintext}")

        _emit(result, as_json, human)

    _run(go())
