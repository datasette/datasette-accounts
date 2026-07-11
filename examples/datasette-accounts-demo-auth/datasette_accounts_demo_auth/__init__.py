"""A development-only demo sign-in provider for datasette-accounts.

**This provider authenticates nobody.** Its "identity provider" is a local HTML
form where you type whatever subject you like — so anyone who can reach the page
can sign in as anyone. It exists to (a) prove the
``datasette_accounts_auth_providers`` hookspec works end to end for an
out-of-tree package and (b) serve as copy-paste scaffolding for a real OAuth /
OIDC provider. It must NEVER be installed on a real deployment.

The whole file is intentionally tiny and touches zero security machinery:
datasette-accounts owns the signed ``state``, CSRF gating of provider POSTs,
``?next=`` validation, the enabled-bit check in front of the mount, the account
gates, provisioning policy, session mint, and the cookie. A provider's only job
is to prove control of some external identity and hand core an
``ExternalIdentity``. See the README for the full contract + security checklist.
"""

import warnings
from urllib.parse import quote

from datasette import Response, hookimpl
from datasette_accounts.providers import (
    AuthProvider,
    ExternalIdentity,
    finish_login,
    make_state,
    read_state,
)

# The pretend IdP page: subject + hint + display-name inputs behind a loud
# development-only banner, submitting (via GET, so the whole loop is browser
# navigations exactly like a real OAuth authorize→callback round-trip) back to
# the provider's callback subpath. No templates, no static files.
_IDP_FORM_HTML = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Demo IdP — development only</title>
<style>
  body {{ font-family: system-ui, sans-serif; max-width: 34rem; margin: 3rem auto;
          padding: 0 1rem; line-height: 1.5; }}
  .banner {{ background: #b91c1c; color: #fff; padding: 1rem 1.25rem;
             border-radius: 8px; font-weight: 600; }}
  .banner code {{ color: #fee; }}
  form {{ margin-top: 1.5rem; display: grid; gap: 1rem; }}
  label {{ display: grid; gap: .35rem; font-weight: 600; }}
  input {{ padding: .5rem; font-size: 1rem; }}
  button {{ padding: .6rem 1rem; font-size: 1rem; cursor: pointer; }}
  p.help {{ color: #444; font-size: .9rem; }}
</style>
</head>
<body>
<div class="banner">
  ⚠ Development only — this page authenticates <strong>nobody</strong>.
  Whatever <code>subject</code> you type is accepted as-is. Never expose this
  provider on a real deployment.
</div>
<h1>Demo identity provider</h1>
<p class="help">
  Stand-in for a real IdP's login screen. Submitting posts the subject back to
  datasette-accounts' callback, carrying the signed <code>state</code> — the
  exact seam a real OAuth <code>redirect_uri</code> would hit.
</p>
<form method="get" action="{callback}">
  <input type="hidden" name="state" value="{state}">
  <label>Subject (the IdP's stable user id — never an email)
    <input name="subject" value="demo-user-1" required></label>
  <label>Username hint (used only to derive a username on first sign-in)
    <input name="username" value="Demo User"></label>
  <label>Display name (stored for audit detail only)
    <input name="name" value="Demo User"></label>
  <button type="submit">Sign in</button>
</form>
</body>
</html>
"""


class DemoProvider(AuthProvider):
    """Fake IdP for development. AUTHENTICATES NOBODY — never enable in
    production. Exercises the exact start → redirect → callback → finish_login
    sequence a real OAuth provider uses."""

    key = "demo"
    label = "Demo (dev only)"

    async def handle(self, datasette, request, subpath):
        if subpath == "start":
            # A link / step-up flow reaches `start` with a signed state already
            # minted by datasette-accounts (intent + actor_id ride in that
            # cookie) — we must carry it through untouched, never re-mint. A
            # fresh login has no state, so we mint a login-intent one. Either
            # way we redirect the visitor to our pretend IdP page, like a real
            # provider redirects to its authorize URL.
            idp = datasette.urls.path("/-/login/provider/demo/idp")
            existing = read_state(datasette, request, provider="demo")
            if existing is not None:
                state = request.args.get("state", "")
                return Response.redirect(f"{idp}?state={quote(state)}")
            response = Response.redirect(idp)
            state = make_state(
                datasette,
                request,
                response,
                provider="demo",
                next=request.args.get("next"),
                intent=request.args.get("intent", "login"),
            )
            # Response.redirect wrote the "Location" header (capital L); append
            # the state to that exact key so we don't emit a second header.
            response.headers["Location"] = f"{idp}?state={quote(state)}"
            return response

        if subpath == "idp":
            # The pretend IdP: a form carrying the state param through, with a
            # loud dev-only banner.
            callback = datasette.urls.path("/-/login/provider/demo/callback")
            return Response.html(
                _IDP_FORM_HTML.format(
                    callback=callback,
                    state=quote(request.args.get("state", "")),
                )
            )

        if subpath == "callback":
            state = read_state(datasette, request, provider="demo")
            if state is None:
                return Response.text("Sign-in failed — start over.", status=400)
            return await finish_login(
                datasette,
                request,
                ExternalIdentity(
                    provider="demo",
                    subject=request.args["subject"],
                    username_hint=request.args.get("username") or None,
                    display_name=request.args.get("name") or None,
                ),
                provider_key="demo",
                state=state,
            )

        return Response.text("Not found", status=404)


@hookimpl
def datasette_accounts_auth_providers(datasette):
    # Loud at load time too: if this package is installed at all, something is
    # probably wrong outside a dev/test/demo environment.
    warnings.warn(
        "datasette-accounts-demo-auth is installed: the 'demo' sign-in provider "
        "authenticates nobody and must never be enabled in production.",
        stacklevel=2,
    )
    return [DemoProvider()]
