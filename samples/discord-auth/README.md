# Discord sign-in sample (`samples/discord-auth`)

A **real-world** OAuth2 sign-in provider for
[datasette-accounts](https://github.com/simonw/datasette-accounts): sign in with
[Discord](https://discord.com/developers/applications). Discord is plain OAuth2
(not OIDC), so it is the worked example of a bespoke provider. Unlike
`examples/datasette-accounts-demo-auth` (a fake IdP that authenticates nobody),
this one really authenticates people.

It is a single loose module (`discord_auth.py`) that Datasette's `--plugins-dir`
imports directly — no packaging. `just dev` loads it, so the dev login page can
show a "Continue with Discord" button. The module owns its routes under
`/-/discord-auth/...` via the ordinary `register_routes` hook (the datasette-paper
model), each wrapped in `@provider_gate("discord")`.

## Setup

1. Create a Discord application at <https://discord.com/developers/applications>.
   Under **OAuth2**, add the redirect URI
   `{base_url}/-/discord-auth/callback` (e.g.
   `http://localhost:8006/-/discord-auth/callback` in dev).
2. Export the app's credentials before starting Datasette:

   ```bash
   export DATASETTE_DISCORD_CLIENT_ID=…
   export DATASETTE_DISCORD_CLIENT_SECRET=…
   ```

3. Load the module and enable the provider (external providers are **disabled by
   default** — installing the module changes nothing until an admin enables it):

   ```bash
   datasette --plugins-dir samples/discord-auth --internal accounts.db …
   datasette accounts enable-provider discord -i accounts.db
   datasette accounts set-signups discord auto -i accounts.db   # or: approval
   ```

The button appears on the login page only once `discord` is enabled **and**
configured. Without the two env vars the provider is harmless: its `configured()`
returns False, so core keeps the button off the login page (and off account
linking) even when an admin has enabled it — the row still shows in the admin
Configuration table, flagged **not configured**, so an operator sees why. As
defense in depth `start` also returns a **503** explainer if hit directly, and
no session can ever be minted.

The button itself is branded via the descriptor's optional `icon` (the
Bootstrap-icons Discord mark, inline SVG with `fill="currentColor"`) and
`brand_color` (`#5865F2`, Discord blurple) — core renders the icon inside the
button and uses the colour as its background with white text.

## What it does

`start` redirects to Discord's authorize URL carrying the core-minted signed
`state`; `callback` exchanges the returned code for a token, reads the Discord
user, and hands core an `ExternalIdentity` keyed on the account's **snowflake id**
(never the username or email — those are mutable). The provider owns these two
routes and wraps each in `@provider_gate("discord")` for the enabled-404 +
CSRF-on-POST gate. Everything else — signed state, `?next=` validation, the
load-bearing enabled re-check inside `finish_login`, account policy, session mint
— is core's job; see the demo package's README for the full provider contract and
security checklist.
