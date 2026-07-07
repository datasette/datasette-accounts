# 03 — Authentication flow

## Password hashing

Copy `datasette-auth-passwords`' `utils.py` verbatim:
- `pbkdf2_sha256$<iterations>$<salt>$<b64hash>`, PBKDF2-HMAC-SHA256, 480 000
  iterations, 16-byte hex salt.
- `verify_password` re-hashes with the embedded salt/iterations and compares with
  `secrets.compare_digest` (constant-time).
- Stdlib only (`hashlib`, `secrets`, `base64`).
- Also expose a `datasette hash-password`-style CLI via `register_commands` for
  scripted account creation.

### Off the event loop (mandatory)

A synchronous 480 000-iteration PBKDF2 call takes ~100–300 ms of CPU and would
block the **entire instance** (every user, every route — Datasette handlers run
on one asyncio event loop) for that duration. An unauthenticated attacker
spamming `POST /-/login/api/authenticate` could serialize and stall the whole
site. Therefore **all KDF work runs off the loop** — login verification, the
dummy-hash verify (below), and hash *generation* in account create /
reset-password / change-password — via `await asyncio.to_thread(...)` (or a
shared executor), **never inline in a handler**.

`passwords.py` exposes async wrappers (e.g. `async def averify_password`,
`async def ahash_password`) and handlers call **only** those; the sync
`verify_password` / `hash_password` are never invoked directly from a request
path. (Residual CPU-exhaustion risk from parallel logins is noted in
[`06-brute-force.md`](06-brute-force.md) — threads unblock the loop but still
burn CPU; a global rate limit is a future mitigation.)

### Password length bounds

Enforce `password_min_length` (default 8, config) **and** a fixed maximum of
**1024 characters** (not configurable) on create / reset / change. An unbounded
attacker-controlled input into the KDF is a needless cost; the cap is one
validation line.

## Session tokens

- Mint: `token = secrets.token_urlsafe(32)`.
- Store: `sha256(token)` as `sessions.token_sha256` (never the raw token).
- Cookie: `datasette.sign(token, "datasette-accounts")` — an **explicit
  namespace** (not the default), so this value can't be confused with anything
  else signed by core or another plugin. `unsign` uses the same namespace.
  ← verify the exact `sign`/`unsign` signature in the pinned Datasette alpha.
- Expiry: absolute, `created_at + session_ttl_days` (default 14).

## Cookie

- Name: **`ds_accounts_session`** (our own; NOT `ds_actor`).
- Value: `datasette.sign(raw_token, "datasette-accounts")`.
- Attributes: `httponly=True`, `samesite="Lax"`, `path="/"`, TTL matches session
  expiry, and `secure` per the **`secure_cookie`** option:
  - `secure_cookie: "auto"` (default) — Secure when the request is HTTPS **or**
    a trusted proxy forwards `X-Forwarded-Proto: https`. TLS is very commonly
    terminated at a reverse proxy (nginx/Caddy/fly/Cloud Run), so a naive
    "request scheme is https" test would ship the cookie **without** Secure in
    exactly the public-facing deployments — hence the forwarded-header check.
    ← verify how the pinned Datasette 1.0 alpha normalizes forwarded headers: if
    core already rewrites `request.scheme` under its proxy/`base_url` setting,
    `auto` can simply trust `request.scheme` (state which, once confirmed).
  - `secure_cookie: true` / `false` — force on/off. `true` is the recommended
    setting for any proxied production deployment.

  See [`08-config.md`](08-config.md) for the option; the proxy-trust signal is
  shared with the IP-trust rule in [`02-data-model.md`](02-data-model.md).

## `actor_from_request` hook

Runs on every request. The DB is the source of truth:

```
1. read ds_accounts_session cookie -> None if absent
2. token = datasette.unsign(cookie, "datasette-accounts")  -> None if tampered
3. row = SELECT * FROM sessions WHERE token_sha256 = sha256(token)
4. if no row OR expires_at <= now:          -> None (and delete expired row)
5. user = SELECT * FROM users WHERE id = row.actor_id
6. if no user OR user.disabled:             -> None
7. update sessions.last_seen_at = now       (throttled — see below)
8. return {"id": user.id, "username": user.username, "is_admin": bool(user.is_admin)}
```

- **`last_seen_at` throttle (step 7):** write only when the stored
  `last_seen_at` is more than **60 seconds** old. Otherwise every single request
  becomes a write on the internal DB's single write connection. (The value is
  only used for the admin session list, so minute-granularity is fine.)
- The expired-row delete in step 4 is the lazy per-token reap; the startup +
  post-login bulk purge in [`02-data-model.md`](02-data-model.md) covers
  abandoned sessions that are never presented again.

Because the actor is rebuilt from the DB each request, disabling/deleting an account
or revoking a session logs the user out on the next request; renames and admin-flag
toggles take effect live without re-login.

## Login (`/-/login`)

Svelte page → JSON `POST` to authenticate endpoint (JSON body → CSRF-exempt).

```
POST /-/login/api/authenticate  { username, password }
  1. if account locked (locked_until > now): 429 + audit(fail)   # ONLY hash-skipping path
  2. row = SELECT * FROM users WHERE username = ?
  3. if row and not row.disabled:
       ok = await averify_password(password, row.password_hash)
     else:
       # unknown username OR disabled account: still spend one verify against a
       # module-level DUMMY_HASH so response timing can't distinguish accounts
       await averify_password(password, DUMMY_HASH)
       ok = False
  4. audit(username, ip, success=ok)
  5. if not ok:
       UPDATE users SET failed_attempts = failed_attempts + 1 WHERE id = ?   # atomic
       # derive lock decision from the post-update value (RETURNING, or re-read on
       # the write connection) — a read-modify-write on the earlier-fetched row
       # undercounts under concurrent bad logins:
       if new_failed_attempts >= lockout_threshold: locked_until = now + lockout_minutes
       return 401 (generic "invalid username or password")
  6. reset failed_attempts = 0, locked_until = NULL
  7. mint token, INSERT session row (ua, ip, expiry)
  8. set cookie; opportunistically purge expired sessions + old login_audit rows
  9. return { redirect: <validated next or "/">, must_change_password: row.must_change_password }
```

- **One PBKDF2 verify on every path** except the locked-account 429 (step 1),
  which returns *before* hashing. `DUMMY_HASH` is a module-level constant in the
  same `pbkdf2_sha256$480000$...$...` format, generated once. This closes the
  username-enumeration timing oracle: an `and` short-circuit that skipped
  `verify_password` for unknown usernames would answer in microseconds while a
  real username paid hundreds of ms. (Do **not** assume the copied
  `verify_password` handles this — the short-circuit is in *this* flow, not in
  the hash helper; fix the flow regardless.)
- Generic error message for locked/unknown/wrong-password to limit enumeration.
  The locked-account 429 (step 1) is the **only** path that both skips the hash
  and is distinguishable from the generic 401 — a consciously accepted
  enumeration signal under the hard-lockout model (see
  [`06-brute-force.md`](06-brute-force.md)).
- All `averify_password` calls run off the event loop (see *Off the event loop*
  above); the dummy verify is no exception.
- If `must_change_password`, the frontend redirects to `/-/account` change-password
  first; the server also enforces it globally (see
  [`05-self-service.md`](05-self-service.md)).

### `?next=` return-URL validation

`?next=` is optional (absent in auth-passwords; we add it). Validate the
**URL-decoded** value and fall back to the default `/` on **any** failure —
`next.startswith("/")` alone is an open redirect (`//evil.example` is
protocol-relative; `/\evil.example` normalizes to an origin in some browsers),
which turns the login page into phishing surface. Rules:

- must start with `/`
- must **not** start with `//` or `/\`
- no `\` anywhere; no CR/LF
- no scheme/authority: reject anything matching `^[a-zA-Z][a-zA-Z0-9+.-]*:`
  before the first `/`
- if Datasette's `base_url` is configured, the final redirect must live under it
  ← verify how the pinned Datasette exposes `base_url` to plugins and how
  sibling redirects handle it

Simplest robust implementation: `urllib.parse.urlparse(next)` must yield empty
`scheme` **and** `netloc`, `path` starts with `/` and not `//`, plus the
explicit backslash check (`urlparse` does not treat `\` as a separator).

## Logout (`/-/logout`)

Our own route (Datasette core's `/-/logout` only clears `ds_actor`, which we don't
use, and would leave the session row alive).

```
POST /-/logout/perform
  DELETE FROM sessions WHERE token_sha256 = sha256(unsign(cookie, "datasette-accounts"))
  clear the cookie
  redirect to "/"
```

Logout mutates, so it is a `POST`. Because `datasette-plugin-router` does not
dispatch by HTTP method (see D17 in [`09-decisions-log.md`](09-decisions-log.md)),
the confirmation **page** and the **mutation** live at distinct paths:
- `GET /-/logout` — a tiny page whose inline JS `fetch()`-POSTs to the mutation
  (JSON body, so the CSRF Content-Type gate passes). A bare GET here only
  renders; it never destroys the session.
- `POST /-/logout/perform` — the mutation. POST-only (a GET returns 405), so it
  cannot be prefetch- or CSRF-triggered.

A `menu_links` hook adds the "Log out" entry (→ `GET /-/logout`) when an actor is
present, and a "Log in" entry (→ `/-/login`) when anonymous.

## CSRF / cross-origin

Protection is **unconditional** and lives in *our* plugin code — it does not
depend on whether an alpha Datasette version happens to ship or enable its
header-based cross-origin middleware. Two gates, enforced by the shared router
decorators (`@require_admin`, the auth/self-service wrappers —
[`01-architecture.md`](01-architecture.md)) on **every** mutation endpoint
(authenticate, all `/-/admin/api/…` ops, change-password, and `POST /-/logout`):

1. **Content-Type gate.** Reject any JSON mutation whose `Content-Type` is not
   `application/json` (415/400). HTML forms can only send
   `application/x-www-form-urlencoded` / `multipart/form-data` / `text/plain`, so
   this blocks form-based CSRF outright.
2. **Origin gate.** If `Sec-Fetch-Site` is present it must be `same-origin` (or
   `none` for direct navigation); else if `Origin` is present it must match the
   request host; else allow (non-browser clients — curl, scripts — send neither).

- **Defense-in-depth action item (not relied upon):** confirm core's header-based
  cross-origin middleware is active in the pinned Datasette too. Our checks hold
  regardless. (Resolves the open item in
  [`09-decisions-log.md`](09-decisions-log.md).)
