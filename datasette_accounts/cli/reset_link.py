"""``datasette accounts reset-link`` — mint a one-time password-reset link."""

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
    _require_user,
    _run,
    _set_password_link,
    _yes_option,
    accounts,
)


@accounts.command(name="reset-link")
@click.argument("username")
@click.option(
    "--ttl-hours",
    type=int,
    default=None,
    help="Link lifetime in hours (default: the reset_link_ttl_hours setting, 24).",
)
@_base_url_option
@click.option("--json", "as_json", is_flag=True, help="Machine-readable output.")
@_yes_option
@_db_options
def reset_link(username, ttl_hours, base_url, as_json, yes, internal, metadata, actor):
    """Mint a one-time password-reset link for an existing account.

    The user stays signed in until they use the link; completing it sets the
    new password and revokes all of their sessions. Any previous invite or
    reset link for the account stops working. The URL is printed exactly once
    (the token is stored hashed and cannot be recovered). Without --base-url
    only the path is printed — prefix your site's origin before sending it.
    """

    async def go():
        ds, db_ = await _open_internal(internal, metadata)
        user = await _require_user(db_, username)
        ttl = (
            ttl_hours
            if ttl_hours is not None
            else security.config(ds, "reset_link_ttl_hours")
        )
        _confirm(
            f"Mint a reset link for {username!r}? Any previous link for the "
            "account stops working.",
            yes,
        )
        raw_token = mint_token()
        minted = await db.mint_password_token(
            db_, _actor_id(actor), user["id"], "reset", token_sha256(raw_token), ttl
        )
        if not minted:
            # _require_user just resolved the account, but never print a link
            # that was not actually minted (e.g. a concurrent delete).
            raise click.ClickException(f"no such user: {username}")
        url = _set_password_link(base_url, raw_token)
        result = {"ok": True, "username": username, "url": url}

        def human():
            click.echo(
                f"Reset link for {username} (shown once, expires in {ttl} hours): {url}"
            )

        _emit(result, as_json, human)

    _run(go())
