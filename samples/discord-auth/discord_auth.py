"""Sample Discord sign-in provider for datasette-accounts.

Unlike ``examples/datasette-accounts-demo-auth`` (a fake IdP that authenticates
nobody), this is a *real* OAuth2 provider — Discord, which is plain OAuth2 (not
OIDC), the case that needs a bespoke provider. It is a single loose module that
Datasette's ``--plugins-dir`` imports directly (no packaging), loaded in dev by
``just dev`` so the login page shows a real "Continue with Discord" button.

Setup:

1. Create a Discord application at https://discord.com/developers/applications
   and, under OAuth2, add the redirect URI
   ``{base_url}/-/login/provider/discord/callback``.
2. Export the app's credentials:
       DATASETTE_DISCORD_CLIENT_ID / DATASETTE_DISCORD_CLIENT_SECRET
3. Enable + open the provider (external providers are disabled by default):
       datasette accounts enable-provider discord -i accounts.db
       datasette accounts set-signups discord auto -i accounts.db   # or approval

Without the two env vars the provider stays harmless: ``start`` returns a 503
explainer and no session can be minted. It stays invisible on the login page
until an admin enables it. See README.md for the full contract + security notes.
"""

from __future__ import annotations

import os
import urllib.parse
from typing import TYPE_CHECKING

import httpx
from datasette import Response, hookimpl

from datasette_accounts.providers import (
    AuthProvider,
    ExternalIdentity,
    finish_login,
    make_state,
    read_state,
)

if TYPE_CHECKING:
    from datasette.app import Datasette
    from datasette.utils.asgi import Request

AUTHORIZE_URL = "https://discord.com/oauth2/authorize"
TOKEN_URL = "https://discord.com/api/oauth2/token"
ME_URL = "https://discord.com/api/users/@me"


class DiscordProvider(AuthProvider):
    """Sign in with Discord (OAuth2 authorization-code flow).

    ``start`` redirects the visitor to Discord's authorize URL carrying the
    core-minted signed ``state``; ``callback`` exchanges the returned code for a
    token, reads the Discord user, and hands core an ``ExternalIdentity`` keyed
    on the account's snowflake id (never the username/email — those are mutable).
    """

    key = "discord"
    label = "Discord"

    def _creds(self) -> tuple[str | None, str | None]:
        return (
            os.environ.get("DATASETTE_DISCORD_CLIENT_ID"),
            os.environ.get("DATASETTE_DISCORD_CLIENT_SECRET"),
        )

    def _redirect_uri(self, datasette: Datasette, request: Request) -> str:
        # Discord requires this to byte-match the redirect URI registered on the
        # app AND the one sent at authorize time, so build it the same way in
        # both start and callback.
        return datasette.absolute_url(
            request,
            datasette.urls.path("/-/login/provider/discord/callback"),
        )

    async def handle(
        self, datasette: Datasette, request: Request, subpath: str
    ) -> Response:
        client_id, client_secret = self._creds()

        if subpath == "start":
            if not (client_id and client_secret):
                return Response.html(
                    "<p>Discord sign-in is not configured — set "
                    "<code>DATASETTE_DISCORD_CLIENT_ID</code> / "
                    "<code>DATASETTE_DISCORD_CLIENT_SECRET</code>.</p>",
                    status=503,
                )

            # A link / step-up flow reaches `start` with a signed state already
            # minted by core (intent + actor_id ride in that cookie): carry it
            # through untouched, never re-mint. A fresh login has no state, so we
            # mint a login-intent one on the response we are about to return.
            response = Response.redirect("about:blank")
            existing = read_state(datasette, request, provider="discord")
            if existing is not None:
                state = request.args.get("state", "")
            else:
                state = make_state(
                    datasette,
                    request,
                    response,
                    provider="discord",
                    next=request.args.get("next"),
                    intent=request.args.get("intent", "login"),
                )
            authorize = (
                AUTHORIZE_URL
                + "?"
                + urllib.parse.urlencode(
                    {
                        "client_id": client_id,
                        "response_type": "code",
                        "redirect_uri": self._redirect_uri(datasette, request),
                        "scope": "identify",
                        "state": state,
                    }
                )
            )
            # Response.redirect wrote the "Location" header (capital L); overwrite
            # that exact key so we don't emit a second, lowercase header.
            response.headers["Location"] = authorize
            return response

        if subpath == "callback":
            # read_state is the CSRF/replay defense for the round-trip: a None
            # result (bad signature, wrong provider, TTL, state mismatch) is a
            # failed sign-in. Never trust intent/actor_id/next from the query —
            # they live in the signed state.
            state = read_state(datasette, request, provider="discord")
            if state is None or "code" not in request.args:
                return Response.text("Sign-in failed — please start over.", status=400)
            async with httpx.AsyncClient() as client:
                token_resp = await client.post(
                    TOKEN_URL,
                    data={
                        "client_id": client_id,
                        "client_secret": client_secret,
                        "grant_type": "authorization_code",
                        "code": request.args["code"],
                        "redirect_uri": self._redirect_uri(datasette, request),
                    },
                )
                token_resp.raise_for_status()
                me_resp = await client.get(
                    ME_URL,
                    headers={
                        "Authorization": "Bearer " + token_resp.json()["access_token"]
                    },
                )
                me_resp.raise_for_status()
            me = me_resp.json()
            return await finish_login(
                datasette,
                request,
                ExternalIdentity(
                    provider="discord",
                    subject=str(me["id"]),  # snowflake — THE stable id
                    username_hint=me.get("username"),
                    display_name=me.get("global_name") or me.get("username"),
                ),
                provider_key="discord",
                state=state,
            )

        return Response.text("Not found", status=404)


@hookimpl
def datasette_accounts_auth_providers(datasette: Datasette) -> list[AuthProvider]:
    return [DiscordProvider()]
