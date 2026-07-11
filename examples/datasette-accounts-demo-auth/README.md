# datasette-accounts-demo-auth

A **development-only** demo sign-in provider for
[datasette-accounts](https://github.com/simonw/datasette-accounts), and the
worked example for writing your own.

> ⚠️ **This provider authenticates nobody.** Its "identity provider" is a local
> HTML form where you type any subject you like, so anyone who reaches the page
> can sign in as anyone. Install it in a dev/test environment to see the
> external sign-in path work end to end, and copy it as scaffolding — never ship
> it on a real deployment.

## What it is for

datasette-accounts lets other packages add sign-in methods (GitHub, Google/OIDC,
Discord, …) through the `datasette_accounts_auth_providers` hookspec. This
package is the smallest possible implementation: ~100 lines, a single module, no
templates and no static files, touching **zero** security machinery. It proves
the hookspec works for an out-of-tree, entry-point-installed distribution and
gives you a starting point.

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

Then the login page shows a **Continue with Demo (dev only)** button.

## The contract

A provider is an `AuthProvider` subclass with a `key`, a `label`, and one async
method:

```python
async def handle(self, datasette: Datasette, request: Request, subpath: str) -> Response
```

Core mounts it at `/-/login/provider/{key}/*` and calls `handle` with the
trailing `subpath`. You choose the subpaths; the conventional pair is `start`
(begin the flow — a redirect to the real IdP, or a form for form-shaped
providers) and `callback` (the IdP sends the user back here). A publish-side
hookimpl returns your instances:

```python
from datasette import hookimpl
from datasette_accounts.providers import AuthProvider

@hookimpl
def datasette_accounts_auth_providers(datasette) -> list[AuthProvider]:
    return [DemoProvider()]
```

Add the `datasette` entry point in your `pyproject.toml` so the package is
discovered when installed (see this package's `pyproject.toml`).

### What core does for you

You never touch any of this — it is enforced *in front of* your `handle`:

- **Mount + routing** — one route dispatches every subpath to you.
- **Enabled gating** — a disabled provider's entire URL surface 404s, including
  mid-flight callbacks. Admins choose which providers are valid at runtime.
- **CSRF** — POSTs to your mount pass core's CSRF gate before your code runs.
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
both login and linking through the same two subpaths.

## Security checklist

The provider contract is deliberately narrow so a provider *cannot* get the
dangerous parts wrong. The rules that remain your responsibility:

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
  proven; the proof is the provider's job. *This demo skips it on purpose — that
  is exactly why it authenticates nobody.*

## How the demo flow runs

1. Login page → **Continue with Demo** → `GET /-/login/provider/demo/start`.
2. `start` mints a login-intent `state`, redirects to
   `/-/login/provider/demo/idp` (the local "pretend IdP") carrying the state.
3. The IdP page (loud dev-only banner) posts the typed `subject` back to
   `GET /-/login/provider/demo/callback?state=…&subject=…`.
4. `callback` validates the state, builds an `ExternalIdentity`, and calls
   `finish_login` — which provisions/approves/mints per the admin's `demo`
   signups setting.

## License

Apache-2.0.
