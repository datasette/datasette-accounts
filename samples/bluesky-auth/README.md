# Bluesky sign-in sample (`samples/bluesky-auth`)

A **real-world** sign-in provider for
[datasette-accounts](https://github.com/simonw/datasette-accounts): sign in
with [Bluesky](https://bsky.app) via its AT Protocol OAuth. Unlike
`samples/discord-auth` and `samples/github-auth` (plain OAuth2, a registered
app + client secret), atproto OAuth is a different shape entirely:

- **Public client, no secret** — `token_endpoint_auth_method: "none"`. There
  is no `CLIENT_SECRET` to export; the app's `client_id` is a URL to a
  client-metadata JSON document this sample serves itself
  (`/-/bluesky-auth/client-metadata.json`), which acts as the registration.
- **PAR + PKCE + DPoP are all mandatory**, not optional hardening. `start`
  pushes the authorization request server-to-server before ever redirecting
  the visitor, and every request to the auth server (PAR, token exchange)
  carries a DPoP proof signed with a fresh per-flow key.
- **Identity resolution happens before the redirect**: handle → DID → PDS →
  the visitor's own authorization server. Bluesky accounts aren't all on one
  server — anyone can run their own PDS — so there's no fixed "authorize
  URL" the way Discord/GitHub have one.
- **A sample-owned SQL table** in the internal DB holds each flow's PKCE
  verifier and per-flow DPoP private key (a private key can't ride in core's
  signed state cookie — `datasette.sign` signs, it does not encrypt). Created
  idempotently by this module's own `startup` hookimpl, since a loose
  `--plugins-dir` module can't add a row to core's `internal_migrations.py`.
- **Identity subject = the DID** (`did:plc:…` / `did:web:…`), never the
  handle (mutable and transferable — a Bluesky user can change or move it)
  and never an email (atproto doesn't expose one). Same rule as GitHub's
  numeric id over its renameable login.

It is a single loose module (`bluesky_auth.py`) that Datasette's
`--plugins-dir` imports directly — no packaging. `just dev` loads it (via
`samples/dev-plugins`, which loads every sample and also relays this
sample's `startup` hookimpl so its flow table gets created), so the dev
login page can show a "Continue with Bluesky" button. The module owns its
routes under `/-/bluesky-auth/...` via the ordinary `register_routes` hook,
each wrapped in `@provider_gate("bluesky")`.

## Production setup (hosting at `https://data.example.com`)

There is no client secret to export and nothing to register on Bluesky's
side — atproto is a public-client protocol, and the metadata document this
sample serves at `/-/bluesky-auth/client-metadata.json` **is** the
registration (auth servers fetch it anonymously during PAR). One env var
plus ordinary HTTPS deployment hygiene:

1. **Install the pieces.** `datasette-accounts` plus `authlib` (a dev-only
   dependency in this repo — a production venv must install it explicitly;
   `httpx` ships with Datasette). Copy `bluesky_auth.py` somewhere and point
   `--plugins-dir` at its directory.

2. **Set the public HTTPS origin and run:**

   ```bash
   DATASETTE_SECRET=<long random value, stable across restarts> \
   DATASETTE_BLUESKY_PUBLIC_URL=https://data.example.com \
   datasette mydata.db --internal accounts.db \
     --plugins-dir /srv/datasette/plugins/bluesky-auth \
     -h 127.0.0.1 -p 8006
   ```

   The provider derives everything from `DATASETTE_BLUESKY_PUBLIC_URL`:
   `client_id` becomes
   `https://data.example.com/-/bluesky-auth/client-metadata.json` and
   `redirect_uri` becomes `https://data.example.com/-/bluesky-auth/callback`
   (a `base_url` subpath, if configured, is honored in both). Two hard
   requirements: valid TLS, and **no auth wall in front of the
   client-metadata path** — if the instance sits behind basic auth or an
   access proxy, exempt `/-/bluesky-auth/client-metadata.json` or PAR fails
   when the auth server can't fetch it. A stable `DATASETTE_SECRET` matters
   too: state and session cookies are signed with it, so an ephemeral secret
   logs everyone out (and kills mid-flight sign-ins) on every restart.

3. **Behind a TLS-terminating proxy** (nginx/Caddy), Datasette sees plain
   HTTP, and datasette-accounts decides the cookies' `Secure` flag from the
   request scheme. Either have the proxy send `X-Forwarded-Proto: https` and
   set, in `datasette.yaml`:

   ```yaml
   plugins:
     datasette-accounts:
       trust_proxy_headers: true   # also fixes client-IP audit/rate caps
   ```

   or force it with `secure_cookie: true`. The OAuth URLs themselves never
   depend on proxy headers — public mode builds them from
   `DATASETTE_BLUESKY_PUBLIC_URL` directly, which is why that env var exists
   instead of deriving the origin from the request.

4. **Enable the provider** (external providers are **disabled by default** —
   installing the module changes nothing until an admin enables it):

   ```bash
   datasette accounts enable-provider bluesky -i accounts.db
   datasette accounts set-signups bluesky auto -i accounts.db   # or: approval
   ```

5. **Verify** before trying a sign-in:

   ```bash
   curl -s https://data.example.com/-/bluesky-auth/client-metadata.json
   ```

   The `client_id` field must equal that exact URL.

As with the other samples, `configured()` returning False (neither env var
set) keeps the button off the login page even if `bluesky` has been enabled,
and `start` 503s as defense in depth if hit directly.

**Sign-in UX to expect**: bsky.social's OAuth pages keep their own session —
being signed into the bsky.app web app does not carry over (it uses the
legacy `createSession` API, not OAuth), so first sign-in always shows
bsky.social's authenticate page; its "remember this account" option removes
the password step on later flows. The consent ("Grant access") screen shows
on every sign-in for this sample: per the atproto OAuth spec, silent
sign-in (auto-approving a previously-granted client) is reserved for
**confidential** clients, and this sample is deliberately a plain public
client (see Deliberate simplifications).

## Local dev walkthrough (the loopback client)

atproto has a special "loopback client" form for exactly this case
(`client_id = "http://localhost?redirect_uri=…&scope=…"`) — no metadata
hosting needed, and real auth servers including `bsky.social` special-case
it. Enable it instead of `DATASETTE_BLUESKY_PUBLIC_URL`:

```bash
DATASETTE_BLUESKY_DEV_LOOPBACK=1 just dev
```

Then, in another shell, enable the provider against the same internal DB
`just dev` uses (`accounts.db`, at the repo root):

```bash
datasette accounts enable-provider bluesky -i accounts.db
datasette accounts set-signups bluesky auto -i accounts.db   # or: approval
```

**Browse via `http://127.0.0.1:8006`, not `http://localhost:8006`.** The
loopback client's `client_id` fixes the host to the literal string
`"localhost"`, but the spec requires the paired `redirect_uri` to use the
literal IP `127.0.0.1` instead (this sample's `_redirect_uri` rewrites
whatever host you actually browsed with to `127.0.0.1`, keeping the port).
Datasette's session cookie is scoped to the host you request pages from —
browse via `localhost` and the cookie set during `start` won't be sent back
when the auth server redirects you to the `127.0.0.1` callback, so `state`
will fail to read back and the flow 400s. Starting from `127.0.0.1` keeps
the whole round trip on one host.

Since `bsky.social` is a real, live auth server, this walkthrough
authenticates against production Bluesky — use a real (or disposable) test
account and its handle (e.g. `alice.example.com` — dots are kept as-is
through username derivation, so that's also what your local username would
be).

> **Verified: 2026-07-11**, end-to-end against production `bsky.social` with
> a real account (custom-domain handle), via the loopback client. The first
> attempt caught one real bug — the no-handle default treated `bsky.social`
> as a PDS, but it is the *entryway authorization server* and 404s
> `/.well-known/oauth-protected-resource` (accounts' PDSes are
> `*.host.bsky.network` hosts) — fixed by using it as the issuer directly.
> Expected UX quirks observed: bsky.social always asks you to authenticate
> (its OAuth session is separate from the bsky.app web app's) and always
> shows the consent screen (loopback/public clients don't qualify for the
> spec's confidential-client-only silent sign-in).

## Entry points

The login button goes straight to `bsky.social`'s own sign-in with no
handle typed (npmx.dev's default too) — `start` sends no `login_hint` and
stores no expected DID, so any account on any PDS can complete the flow.
Visitors on other PDSes or custom domains can instead be sent to
`/-/bluesky-auth/start?handle=alice.example.com` (a bare handle) or
`?handle=did:plc:…` (skips handle resolution entirely) to pin the flow to
one identity — useful for account-linking / step-up links, or a future
handle-entry form on the login page itself. That form is a possible
follow-up; it would need to thread the link/step-up `?state=` through the
form round-trip, which is why v1 skips it.

## Security notes

- Subject is the DID, never the handle or an email.
- The callback checks the returned `iss` against the issuer stored at
  `start` time, **and** independently re-derives the DID's own authoritative
  auth server (DID doc → PDS → protected-resource issuer) before trusting
  the token's `sub` — the load-bearing check the spec requires and the
  reference cookbook emphasizes. Without it, a malicious auth server could
  complete a flow and assert someone else's DID.
- Flow rows are single-use (consumed via an atomic `DELETE … RETURNING`) and
  share the same `provider_state_ttl_minutes` TTL as core's signed state
  cookie, so a stale or replayed callback fails closed.
- Sign-in only: the access/refresh tokens returned by the token exchange are
  discarded immediately after the callback's identity checks — no token
  store, no refresh, no PDS access on this account's behalf.
- A disabled provider can never mint a session: `finish_login` re-checks the
  enabled bit itself, independent of any routing.

## Deliberate simplifications

- **Handle resolution via the public appview** (`public.api.bsky.app`)
  rather than the trustless DNS-TXT + `.well-known` path atproto also
  supports — simpler, at the cost of trusting Bluesky's own appview for the
  handle → DID lookup.
- **No confidential-client `private_key_jwt` mode.** npmx.dev supports this
  via an env-provided signing key + a served JWKS document; this sample is
  always a plain public client.
- **No session/token store keyed by DID.** npmx.dev keeps a 179-day
  DPoP-bound session per account; this sample mints its own
  datasette-accounts session and discards atproto's tokens right away.
- **No `did:web` DIDs with path segments** — only the plain-host form
  (`did:web:example.com`) is supported; `did:web:example.com:user:alice`
  is rejected.

Everything else — signed state, `?next=` validation, account policy, the
one session mint — is core's job; see the demo package's README for the
full provider contract and security checklist.
