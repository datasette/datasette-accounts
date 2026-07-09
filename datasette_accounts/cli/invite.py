"""``datasette accounts invite`` — create an account plus a one-time invite link."""

import click

from .. import db, security
from ..sessions import mint_token, token_sha256
from .base import (
    _actor_id,
    _base_url_option,
    _confirm,
    _db_options,
    _emit,
    _open_internal,
    _run,
    _set_password_link,
    _yes_option,
    accounts,
)


@accounts.command(name="invite")
@click.argument("username")
@click.option("--admin", "is_admin", is_flag=True, help="Create as an admin.")
@click.option(
    "--ttl-hours",
    type=int,
    default=None,
    help="Link lifetime in hours (default: the invite_ttl_hours setting, 72).",
)
@_base_url_option
@click.option("--json", "as_json", is_flag=True, help="Machine-readable output.")
@_yes_option
@_db_options
def invite(
    username, is_admin, ttl_hours, base_url, as_json, yes, internal, metadata, actor
):
    """Create an account with a one-time invite link.

    The account has no usable password until the user opens the link and
    chooses one. The URL is printed exactly once (the token is stored hashed
    and cannot be recovered). Without --base-url only the path is printed —
    prefix your site's origin before sending it.
    """

    async def go():
        ds, db_ = await _open_internal(internal, metadata)
        ttl = (
            ttl_hours
            if ttl_hours is not None
            else security.config(ds, "invite_ttl_hours")
        )
        # Pre-check the common duplicate case for a clean error before the
        # prompt; create_invited_user re-checks atomically.
        if await db.get_user_by_username(db_, username) is not None:
            raise click.ClickException("Username already taken")
        _confirm(
            f"Create {'admin' if is_admin else 'user'} account {username!r} "
            "with an invite link?",
            yes,
        )
        raw_token = mint_token()
        try:
            user_id = await db.create_invited_user(
                db_,
                _actor_id(actor),
                username,
                is_admin,
                token_sha256(raw_token),
                ttl,
            )
        except db.UsernameTakenError:
            raise click.ClickException("Username already taken")
        url = _set_password_link(base_url, raw_token)
        result = {"ok": True, "id": user_id, "username": username, "url": url}

        def human():
            click.echo(f"Invited {username} ({'admin' if is_admin else 'user'}).")
            click.echo(f"Link (shown once, expires in {ttl} hours): {url}")

        _emit(result, as_json, human)

    _run(go())
