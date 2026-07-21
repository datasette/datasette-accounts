# datasette-accounts-demo-auth

A **development-only** demo sign-in provider for
[datasette-accounts](https://github.com/simonw/datasette-accounts), and the
worked example for writing your own.

> ⚠️ **Deliberately insecure — development only.** Its "identity provider" is a
> local HTML form: the first visitor to pick a subject claims it, and from then
> on it is defended only by a 4-digit PIN stored **in plain text** — no hashing,
> no rate limiting, no constant-time compare. Install it in a dev/test
> environment to see the external sign-in path work end to end with a real
> (toy) verification step, and copy it as scaffolding — never ship it on a real
> deployment.

## What it is for

datasette-accounts lets other packages add sign-in methods (GitHub, Google/OIDC,
Discord, …) through the `datasette_accounts_auth_providers` hookspec. This
package is the smallest *realistic* implementation: a single module, no
templates and no static files, with a toy verification step (subject + 4-digit
PIN, claimed on first sign-in) and a provider-owned storage table — while every
genuinely dangerous part (signed state, account gates, sessions) stays in core.
It proves the hookspec works for an out-of-tree, entry-point-installed
distribution, gives dev environments an interactive sign-in that needs no
external accounts, and gives you a starting point.

## Install (dev only)

```bash
pip install -e examples/datasette-accounts-demo-auth   # from a checkout
```

Being installed changes nothing on its own — external providers are **disabled
by default**. An admin enables it explicitly:

```bash
datasette accounts enable-provider demo -i accounts.db
datasette accounts set-signups demo auto -i accounts.db   # or: approval
```

Then the login page shows a **Continue with Demo (dev only)** button. Clicking
it lands on the demo's pretend-IdP page: pick any subject, set a 4-digit PIN on
first sign-in (that claims the subject), and present the same PIN on every
sign-in after.

## The contract

A provider is a small **descriptor** — an `AuthProvider` subclass with three
attributes — plus its **own routes**:

```python
class DemoProvider(AuthProvider):
    key = "demo"                    # KEY_RE slug, unique
    label = "Demo (dev only)"       # rendered as "Continue with {label}"
    start_path = "/-/demo-auth/start"  # absolute path to your start route
```

**Optional branding** — two more class attributes dress up the login button
(the demo sets neither, so it gets the neutral default button):

```python
    icon = '<svg xmlns="http://www.w3.org/2000/svg" ... fill="currentColor" ...>...</svg>'
    brand_color = "#5865F2"   # hex only; button background, text goes white
```

`icon` must be a single inline `<svg>…</svg>` element — use
`fill="currentColor"` so it inherits the button's text colour. `brand_color`
must be a plain hex colour. Startup validates both shapes and fails loudly on
anything else. See the Discord provider (`datasette-accounts-discord`) for a
real pair.

**Optional** `configured(self, datasette) -> bool` — override it to report
whether the provider's deployment config (OAuth client id/secret, etc.) is
actually present. It defaults to `True` (the demo needs nothing, so it inherits
that). When it returns `False`, core keeps the provider off the login page and
out of account-linking targets even while an admin has it *enabled* — `enabled`
is runtime policy, `configured` is deployment state. The admin Configuration
table still lists the provider, flagged **not configured**.

`configured()` is usually a plain sync method (a fixed set of env vars, checked
instantly — see the Discord provider, which returns `False` until its two env
vars are set). It may instead be `async def` and return an awaited bool, for a
provider whose readiness genuinely depends on a runtime, DB-backed value that
can't be read synchronously:

```python
    async def configured(self, datasette):
        return await some_async_readiness_check(datasette)
```

Core awaits the result only when it is itself awaitable, so an existing sync
override needs no change.

You register your routes with the ordinary Datasette `register_routes` hook,
under your own `/-/{plugin}/...` prefix (the datasette-paper model — plugins own
their routes). The conventional handlers are `start` (begin the flow — a redirect
to the real IdP, or a form for form-shaped providers) and `callback` (the IdP
sends the user back here). `start_path` is where the login button and the
link/step-up flows point the visitor. Two hookimpls publish the provider and its
routes:

```python
from datasette import Response, hookimpl
from datasette_accounts.providers import AuthProvider, provider_gate

@provider_gate("demo")
async def start(datasette, request) -> Response: ...

@provider_gate("demo")
async def callback(datasette, request) -> Response: ...

@hookimpl
def register_routes():
    return [
        (r"/-/demo-auth/start$", start),
        (r"/-/demo-auth/callback$", callback),
    ]

@hookimpl
def datasette_accounts_auth_providers(datasette) -> list[AuthProvider]:
    return [DemoProvider()]
```

Add the `datasette` entry point in your `pyproject.toml` so the package is
discovered when installed (see this package's `pyproject.toml`).

### What core does for you

You own your routes, but core still owns every dangerous part:

- **`@provider_gate(key)`** — wrap each route in this one-line decorator to get
  the guarantees the old core mount gave: a disabled provider's whole URL surface
  **404s** (including mid-flight callbacks), **POSTs are CSRF-gated** before your
  code runs, and non-GET/HEAD/POST methods **405**. It is optional but
  recommended (see the security checklist). One consequence: the CSRF gate
  expects `Content-Type: application/json` (core's own pages POST JSON), so a
  plain HTML `<form method="post">` will be rejected. Browser-form providers —
  this demo included — submit via **GET carrying the signed `state`** instead,
  exactly the shape of a real OAuth redirect; `read_state` is the CSRF defense
  on that leg.
- **Enabled gating is enforced regardless** — `finish_login` re-checks the
  provider's enabled bit before any mint / provision / link, so even a route you
  forgot to wrap in `provider_gate` cannot sign anyone in while the provider is
  disabled. `provider_gate` is defence in depth; `finish_login` is the
  load-bearing control.
- **Signed `state`** — `make_state` / `read_state` mint and validate the signed,
  cookie-backed OAuth `state` (double-submit, TTL, provider-bound). You never
  hand-roll `state`.
- **`?next=` validation** — the post-login redirect target is validated when the
  state is minted and again when it is consumed.
- **Account policy** — `finish_login` runs the account gates (disabled /
  expired / pending), the per-provider **signups** policy (off / require
  approval / auto-activate), abuse caps, username derivation, the approval
  queue, session mint, and the session cookie.

### What you implement

Prove control of an external identity, then hand core an `ExternalIdentity` and
call `finish_login`:

```python
from datasette_accounts.providers import (
    ExternalIdentity, finish_login, make_state, read_state,
)

# start: mint state, redirect to the IdP (here: our local pretend IdP page)
response = Response.redirect(idp_authorize_url)
state = make_state(datasette, request, response, provider="demo",
                   next=request.args.get("next"))
# ...carry `state` into the authorize URL, like a real OAuth start...

# callback: validate state, build the identity, finish
state = read_state(datasette, request, provider="demo")
if state is None:
    return Response.text("Sign-in failed — start over.", status=400)
return await finish_login(
    datasette, request,
    ExternalIdentity(
        provider="demo",
        subject=idp_stable_user_id,       # NEVER an email
        username_hint=idp_login_name,     # provisioning only
        display_name=idp_display_name,    # audit detail only
    ),
    provider_key="demo", state=state,
)
```

`finish_login` maps `(provider, subject)` to an account through the identities
table, applies the signups policy for a first-seen identity, and mints (or
routes to the approval queue). A **link / step-up** flow reaches your `start`
with a signed state already minted by core — carry it through untouched rather
than re-minting (see this package's `start` handler). The demo package handles
both login and linking through the same routes.

You may also hand `finish_login` a `LocalIdentity(user_id)` when you have
**already** resolved an existing account (the built-in password flow does this
for a login / invite / reset completion) — but external providers always build
an `ExternalIdentity` and let core do the mapping.

## Provider-owned storage

A stateful provider needs its **own** table(s). A third-party package can't
append to core's `internal_migrations.py`, so create them idempotently in a
`startup` hookimpl against the internal database — the same pattern the
Bluesky provider uses for its OAuth-flow table:

```python
@hookimpl
def startup(datasette):
    async def inner():
        internal = datasette.get_internal_database()
        await internal.execute_write(
            "CREATE TABLE IF NOT EXISTS demo_auth_pins (...)"
        )
    return inner
```

Prefix the table name with your package (here `demo_auth_…`) so it can never
collide with core's `datasette_accounts_*` tables or another plugin's. Never
write to core's tables — they are not public API.

What this demo *stores* is the anti-pattern half of the lesson: a raw plaintext
PIN, compared with a plain `!=`, with unlimited retries. A real credential
store hashes with a KDF (see core's PBKDF2 in `passwords.py`), compares in
constant time, and rate-limits — and a real *OAuth* provider stores no
credentials at all, because the IdP proves the identity via token exchange.
Copy the table-creation pattern; never copy the column.

## Token hygiene — patterns to copy, not a shared helper

A provider that mints its own one-time tokens (a magic-link-style flow, say)
needs its **own** token table. Core's invite / reset token helpers are **not**
public API — don't import from `datasette_accounts.db`'s token helpers, and
don't write to core's tables. Copy the pattern core itself uses:

- store a **sha256 hash** of the token, never the raw value;
- **single-use, claim-by-delete**: redeeming a token is a `DELETE` (with
  `RETURNING`, or equivalent) inside your write transaction, so a double-submit
  race or an expired-but-unpurged link both simply find nothing to claim;
- a **TTL**, checked in the same delete (an expired row is indistinguishable
  from a missing one to the caller);
- **one live token per target** — minting a new one invalidates whatever the
  target already had, so an old, forgotten link can never be redeemed alongside
  a fresh one.

A shared token helper may be extracted from core later once a second real
consumer exists; for now, treat this as a pattern to reimplement, not a
dependency to reach for.

## Security checklist

The provider contract is deliberately narrow so a provider *cannot* get the
dangerous parts wrong. The rules that remain your responsibility:

- **Wrap every route in `@provider_gate(key)`.** It gives each route the
  enabled-404 + CSRF-on-POST + method gate the old core mount enforced centrally.
  Even if you forget, `finish_login` refuses a disabled provider — but a forgotten
  gate leaves a live URL surface on a disabled provider, so wrap them all.
- **Never match accounts by email.** Map only by the IdP's **stable subject id**
  (`ExternalIdentity.subject`). Emails change owners and are spoofable; core
  never uses them for matching, and neither should you. Pass `email` only as
  audit detail.
- **Never set cookies or build an actor.** Sessions are core's job — always end
  a flow by returning `await finish_login(...)`. Providers that mint their own
  session bypass every account gate.
- **Always `read_state` on the callback.** It is the CSRF/replay defense for the
  redirect round-trip. Treat a `None` result as a failed sign-in. Never trust
  `intent`, `actor_id`, or `next` from the query string — they live in the
  signed state.
- **Use the IdP's real, stable subject.** Not a display name, not a username —
  those change. If the IdP offers a numeric/opaque id, use it.
- **Verify the IdP's response** (signature / token exchange / nonce) before
  building the `ExternalIdentity`. Core trusts that the subject you pass is
  proven; the proof is the provider's job. *This demo's proof is a deliberately
  toy one — a plaintext 4-digit PIN, first-come subject claiming, unlimited
  retries, and the PIN riding in the query string — which is exactly why it
  must never reach production.*

## How the demo flow runs

1. Login page → **Continue with Demo** → `GET /-/demo-auth/start`.
2. `start` mints a login-intent `state` (or carries a core-minted link/step-up
   state through untouched), redirects to `/-/demo-auth/idp` (the local
   "pretend IdP") carrying the state.
3. The IdP page (loud dev-only banner) submits the typed `subject` + `pin` back
   to `GET /-/demo-auth/callback?state=…&subject=…&pin=…`.
4. `callback` validates the state, then runs the toy proof-of-control: an
   unclaimed subject is claimed with the typed PIN; a claimed subject's PIN
   must match, else the visitor bounces back to the form with an error.
5. On a good PIN, `callback` builds an `ExternalIdentity` and calls
   `finish_login` — which provisions/approves/mints per the admin's `demo`
   signups setting.

For a real-world, non-toy provider (OAuth2 token exchange, `configured()` gated
on env vars, a real IdP round-trip), see the `datasette-accounts-discord`,
`datasette-accounts-github`, and `datasette-accounts-bluesky` sibling packages.

## License

Apache-2.0.
