"""A development-only demo sign-in provider for datasette-accounts.

**Deliberately insecure — development only.** The "identity provider" is a local
HTML form: the first visitor to type an unclaimed subject owns it, and from then
on the subject is defended by a 4-digit PIN stored **in plain text**. Every
piece of that is wrong on purpose, so the demo has a real verification step and
a real UI without pretending to be secure:

* the PIN is stored raw — no hashing, no KDF (real code: core's PBKDF2);
* no rate limiting or lockout — 4 digits is 10,000 guesses;
* the comparison is a plain ``!=`` — not constant-time;
* the PIN rides in the query string (the form submits via GET so the whole
  loop is browser navigations, exactly like a real OAuth authorize→callback
  round-trip) — visible in history and server logs;
* unclaimed subjects are first-come-first-served.

It exists to (a) prove the ``datasette_accounts_auth_providers`` hookspec works
end to end for an out-of-tree package, (b) serve as copy-paste scaffolding for
a real provider — including the provider-owned-storage pattern a stateful
provider needs — and (c) give dev environments an interactive sign-in that
needs no external accounts. It must NEVER be installed on a real deployment.

datasette-accounts still owns every genuinely dangerous part: the signed
``state``, the account gates, provisioning policy, session mint, and the
cookie, and it re-checks the provider's enabled bit inside ``finish_login``.
The provider owns its own routes (the ordinary Datasette ``register_routes``
hook) and wraps each one in ``@provider_gate`` for the enabled-404 and method
gating; ``?next=`` validation lives in ``make_state``. A provider's only job is
to prove control of some external identity and hand core an
``ExternalIdentity`` — the PIN check is this demo's (toy) version of that
proof. See the README for the full contract + security checklist.
"""

from __future__ import annotations

import re
import warnings
from typing import TYPE_CHECKING
from urllib.parse import quote

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

# The pretend IdP's own "user database" — independent of datasette-accounts
# accounts, the way a real IdP's user store is. A real provider never stores
# credentials at all (OAuth providers prove identity via token exchange; the
# built-in password provider uses core's PBKDF2 machinery) — this table is the
# demo's deliberate anti-pattern: a raw plaintext pin and nothing else. Created
# idempotently in the `startup` hookimpl below because a third-party package
# can't append to core's internal_migrations.py (same pattern as the bluesky
# provider's flow table).
PINS_TABLE = "demo_auth_pins"

_CREATE_PINS_TABLE = f"""
CREATE TABLE IF NOT EXISTS {PINS_TABLE} (
    subject TEXT PRIMARY KEY,  -- claimed by the first visitor to sign in with it
    pin TEXT NOT NULL,         -- PLAIN TEXT on purpose. Never copy this column.
    created_at TEXT NOT NULL   -- millisecond ISO + offset, the repo convention
)
"""

_PIN_RE = re.compile(r"^\d{4}$")

# Rendered error messages come ONLY from this fixed dict — the `error` query
# arg selects a constant, it is never interpolated into the page.
_ERRORS = {
    "wrong-pin": "Wrong PIN for that subject.",
    "bad-pin": "PIN must be exactly 4 digits.",
}

# The pretend IdP page: subject + PIN + hint + display-name inputs behind a loud
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
  .error {{ background: #fef2f2; border: 1px solid #b91c1c; color: #b91c1c;
            padding: .6rem .9rem; border-radius: 6px; margin-top: 1.5rem;
            font-weight: 600; }}
  form {{ margin-top: 1.5rem; display: grid; gap: 1rem; }}
  label {{ display: grid; gap: .35rem; font-weight: 600; }}
  input {{ padding: .5rem; font-size: 1rem; }}
  button {{ padding: .6rem 1rem; font-size: 1rem; cursor: pointer; }}
  p.help {{ color: #444; font-size: .9rem; }}
</style>
</head>
<body>
<div class="banner">
  ⚠ Development only — this toy IdP stores PINs in plain text with no rate
  limiting, and unclaimed subjects are first-come-first-served. Never expose
  this provider on a real deployment.
</div>
<h1>Demo identity provider</h1>
<p class="help">
  Stand-in for a real IdP's login screen. The first sign-in with a new
  <code>subject</code> claims it and sets its PIN; later sign-ins must present
  the same PIN. Submitting sends the result back to datasette-accounts'
  callback, carrying the signed <code>state</code> — the exact seam a real
  OAuth <code>redirect_uri</code> would hit.
</p>
{error}
<form method="get" action="{callback}">
  <input type="hidden" name="state" value="{state}">
  <label>Subject (the IdP's stable user id — never an email)
    <input name="subject" value="demo-user-1" required></label>
  <label>PIN (4 digits — a new subject is claimed with the PIN you type)
    <input name="pin" inputmode="numeric" pattern="[0-9]{{4}}" maxlength="4"
           required></label>
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
    """Toy IdP for development: subject + plaintext 4-digit PIN, first-come
    subject claiming — DELIBERATELY INSECURE, never enable in production.
    Exercises the exact start → redirect → callback → finish_login sequence a
    real OAuth provider uses. Its routes are registered below via the ordinary
    ``register_routes`` hook; ``start_path`` is where the login button and
    link/step-up forwards point."""

    key = "demo"
    label = "Demo (dev only)"
    start_path = "/-/demo-auth/start"


@provider_gate("demo")
async def start(datasette: Datasette, request: Request) -> Response:
    # A link / step-up flow reaches `start` with a signed state already minted by
    # datasette-accounts (intent + actor_id ride in that cookie) — we must carry
    # it through untouched, never re-mint. A fresh login has no state, so we mint
    # a login-intent one. Either way we redirect the visitor to our pretend IdP
    # page, like a real provider redirects to its authorize URL.
    idp = datasette.urls.path("/-/demo-auth/idp")
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
    # Response.redirect wrote the "Location" header (capital L); append the state
    # to that exact key so we don't emit a second header.
    response.headers["Location"] = f"{idp}?state={quote(state)}"
    return response


@provider_gate("demo")
async def idp(datasette: Datasette, request: Request) -> Response:
    # The pretend IdP: a form carrying the state param through, with a loud
    # dev-only banner. A failed PIN check redirects back here with `error=` set
    # to one of the _ERRORS keys — anything else renders no message.
    callback = datasette.urls.path("/-/demo-auth/callback")
    message = _ERRORS.get(request.args.get("error", ""))
    return Response.html(
        _IDP_FORM_HTML.format(
            callback=callback,
            state=quote(request.args.get("state", "")),
            error=f'<div class="error">{message}</div>' if message else "",
        )
    )


def _retry(datasette: Datasette, request: Request, error: str) -> Response:
    """Bounce a failed PIN check back to the IdP form. `error` is one of the
    _ERRORS keys (never user input); the state rides along in the query so the
    visitor can retry within the state TTL."""
    idp = datasette.urls.path("/-/demo-auth/idp")
    state = quote(request.args.get("state", ""))
    return Response.redirect(f"{idp}?state={state}&error={error}")


@provider_gate("demo")
async def callback(datasette: Datasette, request: Request) -> Response:
    state = read_state(datasette, request, provider="demo")
    if state is None:
        return Response.text("Sign-in failed — start over.", status=400)
    subject = request.args.get("subject") or ""
    if not subject:
        return Response.text("Sign-in failed — start over.", status=400)

    # The demo's toy proof-of-control: claim-or-verify the subject's PIN. This
    # is the seam where a real provider does its real verification (token
    # exchange, signature check) BEFORE building the ExternalIdentity — core
    # trusts that the subject you pass is proven. Note a real callback receives
    # a one-time code, never raw credentials; see the README's token-hygiene
    # section for the single-use-code pattern this demo skips.
    pin = request.args.get("pin") or ""
    if not _PIN_RE.match(pin):
        return _retry(datasette, request, "bad-pin")
    internal = datasette.get_internal_database()
    row = (
        await internal.execute(
            f"SELECT pin FROM {PINS_TABLE} WHERE subject = ?", [subject]
        )
    ).first()
    if row is None:
        # First sign-in claims the subject — the pretend IdP "registers" the
        # visitor. This happens regardless of core's signups policy: the IdP's
        # user store is independent of whether datasette-accounts will
        # provision an account for it (finish_login decides that next).
        await internal.execute_write(
            f"INSERT INTO {PINS_TABLE} (subject, pin, created_at) VALUES "
            "(?, ?, strftime('%Y-%m-%dT%H:%M:%f','now')||'+00:00')",
            [subject, pin],
        )
    elif row["pin"] != pin:
        # Plaintext, non-constant-time, unlimited retries: every one of those
        # is a demo-only shortcut — see the module docstring.
        return _retry(datasette, request, "wrong-pin")
    return await finish_login(
        datasette,
        request,
        ExternalIdentity(
            provider="demo",
            subject=subject,
            username_hint=request.args.get("username") or None,
            display_name=request.args.get("name") or None,
        ),
        provider_key="demo",
        state=state,
    )


@hookimpl
def startup(datasette: Datasette):
    # A third-party package can't append a row to core's internal_migrations.py,
    # so the PIN table is created idempotently here instead (the same pattern
    # the bluesky provider uses for its flow table). As an installed package
    # this startup hookimpl fires natively; CREATE TABLE IF NOT EXISTS is safe
    # on every boot.
    async def inner():
        internal = datasette.get_internal_database()
        await internal.execute_write(_CREATE_PINS_TABLE)

    return inner


@hookimpl
def register_routes():
    # The provider owns its URL surface under /-/demo-auth/... (design D3b). Each
    # handler is wrapped in @provider_gate("demo") above, so a disabled demo
    # provider 404s here — the same guarantees the old core mount gave, now the
    # provider's own responsibility.
    return [
        (r"/-/demo-auth/start$", start),
        (r"/-/demo-auth/idp$", idp),
        (r"/-/demo-auth/callback$", callback),
    ]


@hookimpl
def datasette_accounts_auth_providers(datasette: Datasette) -> list[AuthProvider]:
    # Loud at load time too: if this package is installed at all, something is
    # probably wrong outside a dev/test/demo environment.
    warnings.warn(
        "datasette-accounts-demo-auth is installed: the 'demo' sign-in provider "
        "stores plaintext 4-digit PINs with no rate limiting and must never be "
        "enabled in production.",
        stacklevel=2,
    )
    return [DemoProvider()]
