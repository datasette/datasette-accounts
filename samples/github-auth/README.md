# GitHub sign-in sample (`samples/github-auth`)

A second **real-world** OAuth2 sign-in provider for
[datasette-accounts](https://github.com/simonw/datasette-accounts), next to
`samples/discord-auth`: sign in with [GitHub](https://github.com/settings/developers).
GitHub is probably the easiest mainstream OAuth2 IdP — plain authorization-code
flow (no PKCE required), one token exchange, and `GET /user` returns a stable
numeric `id` — so this sample is a near copy of the Discord one and a good
diff-read to see what changes between providers.

It is a single loose module (`github_auth.py`) that Datasette's `--plugins-dir`
imports directly — no packaging. `just dev` loads it (via `samples/dev-plugins`,
which loads every sample), so the dev login page can show a "Continue with
GitHub" button. The module owns its routes under `/-/github-auth/...` via the
ordinary `register_routes` hook (the datasette-paper model), each wrapped in
`@provider_gate("github")`.

## Setup

1. Create a GitHub OAuth app at <https://github.com/settings/developers>
   (**OAuth Apps → New OAuth App**) and set its **Authorization callback URL** to
   `{base_url}/-/github-auth/callback` (e.g.
   `http://localhost:8006/-/github-auth/callback` in dev).
2. Export the app's credentials before starting Datasette:

   ```bash
   export DATASETTE_GITHUB_CLIENT_ID=…
   export DATASETTE_GITHUB_CLIENT_SECRET=…
   ```

3. Load the module and enable the provider (external providers are **disabled by
   default** — installing the module changes nothing until an admin enables it):

   ```bash
   datasette --plugins-dir samples/github-auth --internal accounts.db …
   datasette accounts enable-provider github -i accounts.db
   datasette accounts set-signups github auto -i accounts.db   # or: approval
   ```

The button appears on the login page only once `github` is enabled **and**
configured. Without the two env vars the provider is harmless: its `configured()`
returns False, so core keeps the button off the login page (and off account
linking) even when an admin has enabled it — the row still shows in the admin
Configuration table, flagged **not configured**, so an operator sees why. As
defense in depth `start` also returns a **503** explainer if hit directly, and
no session can ever be minted.

The button itself is branded via the descriptor's optional `icon` (the
Bootstrap-icons GitHub mark, inline SVG with `fill="currentColor"`) and
`brand_color` (`#24292F`, GitHub's near-black) — core renders the icon inside
the button and uses the colour as its background with white text.

## What it does

`start` redirects to GitHub's authorize URL carrying the core-minted signed
`state` (no `scope` is requested — the default grants read-only access to public
information, all `/user` needs); `callback` exchanges the returned code for a
token and hands core an `ExternalIdentity` keyed on the account's **numeric id**
(never the login or email — logins can be renamed). One GitHub quirk worth
copying: the token endpoint reports errors as HTTP **200** with an
`{"error": ...}` body, so the callback gates on the presence of `access_token`
rather than trusting `raise_for_status`. The provider owns these two routes and
wraps each in `@provider_gate("github")` for the enabled-404 + CSRF-on-POST
gate. Everything else — signed state, `?next=` validation, the load-bearing
enabled re-check inside `finish_login`, account policy, session mint — is core's
job; see the demo package's README for the full provider contract and security
checklist.
