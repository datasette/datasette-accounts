"""Sample GitHub sign-in provider for datasette-accounts.

The second real OAuth2 sample next to ``samples/discord-auth`` — GitHub is
probably the easiest mainstream OAuth2 IdP: plain authorization-code flow (no
PKCE required), one token exchange, and ``GET /user`` returns a stable numeric
``id``. Like the Discord sample it is a single loose module that Datasette's
``--plugins-dir`` imports directly (no packaging); ``just dev`` loads it via
``samples/dev-plugins``.

Setup:

1. Create a GitHub OAuth app at https://github.com/settings/developers and set
   its authorization callback URL to ``{base_url}/-/github-auth/callback``.
2. Export the app's credentials:
       DATASETTE_GITHUB_CLIENT_ID / DATASETTE_GITHUB_CLIENT_SECRET
3. Enable + open the provider (external providers are disabled by default):
       datasette accounts enable-provider github -i accounts.db
       datasette accounts set-signups github auto -i accounts.db   # or approval

Without the two env vars the provider stays harmless: ``configured`` returns
False, so core keeps its button off the login page (and off account linking)
even when an admin has enabled it; ``start`` also returns a 503 explainer as
defense in depth, and no session can be minted. See README.md for the full
contract + security notes.
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
    provider_gate,
    read_state,
)

if TYPE_CHECKING:
    from datasette.app import Datasette
    from datasette.utils.asgi import Request

AUTHORIZE_URL = "https://github.com/login/oauth/authorize"
TOKEN_URL = "https://github.com/login/oauth/access_token"
ME_URL = "https://api.github.com/user"


class GitHubProvider(AuthProvider):
    """Sign in with GitHub (OAuth2 authorization-code flow).

    ``start`` redirects the visitor to GitHub's authorize URL carrying the
    core-minted signed ``state``; ``callback`` exchanges the returned code for a
    token, reads the GitHub user, and hands core an ``ExternalIdentity`` keyed
    on the account's numeric id (never the login or email — those are mutable).
    The provider owns its own routes under ``/-/github-auth/...`` (registered
    below); ``start_path`` is where the login button + link/step-up point.
    """

    key = "github"
    label = "GitHub"
    start_path = "/-/github-auth/start"
    # Login-button branding: GitHub's Bootstrap-icons mark (bi-github, MIT)
    # with fill="currentColor" so it inherits the button's white text, plus
    # GitHub's near-black brand colour as the button background.
    icon = (
        '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" '
        'fill="currentColor" class="bi bi-github" viewBox="0 0 16 16">'
        '<path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55'
        "-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23"
        "-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 "
        "1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 "
        "0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64"
        "-.18 1.32-.27 2-.27s1.36.09 2 .27c1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 "
        "1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25"
        ".54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.01 8.01 0 "
        '0 0 16 8c0-4.42-3.58-8-8-8"/>'
        "</svg>"
    )
    brand_color = "#24292F"

    def configured(self, datasette: Datasette) -> bool:
        # Ready to authenticate only when both OAuth2 credentials are present.
        # Until then the login button + link targets hide it (core respects
        # this), and `start` 503s as defense in depth if someone hits it directly.
        client_id, client_secret = _creds()
        return bool(client_id and client_secret)


def _creds() -> tuple[str | None, str | None]:
    return (
        os.environ.get("DATASETTE_GITHUB_CLIENT_ID"),
        os.environ.get("DATASETTE_GITHUB_CLIENT_SECRET"),
    )


def _redirect_uri(datasette: Datasette, request: Request) -> str:
    # GitHub requires this to match the OAuth app's registered callback URL AND
    # the one sent at authorize time, so build it the same way in both start
    # and callback.
    return datasette.absolute_url(
        request,
        datasette.urls.path("/-/github-auth/callback"),
    )


@provider_gate("github")
async def start(datasette: Datasette, request: Request) -> Response:
    client_id, client_secret = _creds()
    if not (client_id and client_secret):
        return Response.html(
            "<p>GitHub sign-in is not configured — set "
            "<code>DATASETTE_GITHUB_CLIENT_ID</code> / "
            "<code>DATASETTE_GITHUB_CLIENT_SECRET</code>.</p>",
            status=503,
        )

    # A link / step-up flow reaches `start` with a signed state already minted by
    # core (intent + actor_id ride in that cookie): carry it through untouched,
    # never re-mint. A fresh login has no state, so we mint a login-intent one on
    # the response we are about to return.
    response = Response.redirect("about:blank")
    existing = read_state(datasette, request, provider="github")
    if existing is not None:
        state = request.args.get("state", "")
    else:
        state = make_state(
            datasette,
            request,
            response,
            provider="github",
            next=request.args.get("next"),
            intent=request.args.get("intent", "login"),
        )
    authorize = (
        AUTHORIZE_URL
        + "?"
        + urllib.parse.urlencode(
            {
                "client_id": client_id,
                "redirect_uri": _redirect_uri(datasette, request),
                "state": state,
                # No `scope`: an empty scope grants read-only access to public
                # information, which is all /user needs for id/login/name.
            }
        )
    )
    # Response.redirect wrote the "Location" header (capital L); overwrite that
    # exact key so we don't emit a second, lowercase header.
    response.headers["Location"] = authorize
    return response


@provider_gate("github")
async def callback(datasette: Datasette, request: Request) -> Response:
    client_id, client_secret = _creds()
    # read_state is the CSRF/replay defense for the round-trip: a None result
    # (bad signature, wrong provider, TTL, state mismatch) is a failed sign-in.
    # Never trust intent/actor_id/next from the query — they live in the signed
    # state.
    state = read_state(datasette, request, provider="github")
    if state is None or "code" not in request.args:
        return Response.text("Sign-in failed — please start over.", status=400)
    async with httpx.AsyncClient() as client:
        token_resp = await client.post(
            TOKEN_URL,
            data={
                "client_id": client_id,
                "client_secret": client_secret,
                "code": request.args["code"],
                "redirect_uri": _redirect_uri(datasette, request),
            },
            # Without this GitHub answers form-encoded.
            headers={"Accept": "application/json"},
        )
        token_resp.raise_for_status()
        token = token_resp.json().get("access_token")
        # GitHub reports errors (bad/expired code, mismatched redirect_uri) as
        # HTTP 200 with an {"error": ...} body — raise_for_status can't see
        # them, so gate on the token itself.
        if not token:
            return Response.text("Sign-in failed — please start over.", status=400)
        me_resp = await client.get(
            ME_URL,
            headers={
                "Authorization": "Bearer " + token,
                "Accept": "application/vnd.github+json",
            },
        )
        me_resp.raise_for_status()
    me = me_resp.json()
    return await finish_login(
        datasette,
        request,
        ExternalIdentity(
            provider="github",
            subject=str(me["id"]),  # numeric id — THE stable id (logins rename)
            username_hint=me.get("login"),
            display_name=me.get("name") or me.get("login"),
        ),
        provider_key="github",
        state=state,
    )


@hookimpl
def register_routes():
    # The provider owns its URL surface under /-/github-auth/... (design D3b).
    # Both handlers are wrapped in @provider_gate("github"), so a disabled
    # provider 404s and POSTs are CSRF-gated — the guarantees the old core mount
    # used to give, now the provider's own responsibility.
    return [
        (r"/-/github-auth/start$", start),
        (r"/-/github-auth/callback$", callback),
    ]


@hookimpl
def datasette_accounts_auth_providers(datasette: Datasette) -> list[AuthProvider]:
    return [GitHubProvider()]
