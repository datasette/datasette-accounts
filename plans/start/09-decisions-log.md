# 09 — Decisions log

Each row: the decision made, alternatives considered, and why. These came out of a
question-by-question grilling session.

## D1 — Permission scope: **Accounts + admin flag only**
This plugin owns identity (accounts, passwords, sessions, one `is_admin` flag).
Resource-level permissions are delegated to `datasette-acl` / config `allow` blocks,
which consume the actor we emit.
- *Rejected:* "accounts + group membership" (owning user↔group assignment) and "full
  ACL in this plugin" (rebuilding datasette-acl). Both overlap or duplicate acl.

## D2 — Session model: **Server-side sessions**
Random token in a signed cookie; a `sessions` table looked up per request. Enables
per-device revocation, "log out everywhere", an admin session list, and expiry
independent of Datasette's secret.
- *Rejected:* "DB is source of truth via account-id cookie" (account-level revoke
  only, no per-device) and "stateless like auth-passwords" (can't revoke before
  expiry). User explicitly preferred server-side after comparing.

## D3 — Identity: **Immutable ULID `id` + mutable `username`**
Actor `id` is a ULID generated at creation and never changes; it's the permanent join
key to profiles/acl. `username` is a separate unique, mutable login credential.
- *Rejected:* "username IS the id" (renames orphan profile/acl/session links) and
  "email as login" (no separate username).

## D4 — Bootstrap: **`datasette --root`**
Root is always admin and creates the first real admin; root is not a DB row. No
secrets in config, exactly how datasette-acl bootstraps.
- *Rejected:* a `create-admin` CLI (deferred as a future convenience) and a
  config-seeded admin (puts a credential in metadata, blurs "accounts live in DB").

## D5 — Admin gate: **Real action, self-answered**
Register `datasette-accounts-admin` and answer it (`root OR is_admin`) so it's
composable with acl/config and visible to introspection.
- *Rejected:* internal-only `require_admin()` helper (self-contained but invisible to
  Datasette's permission system, can't be granted externally).

## D6 — Frontend split: **Svelte everything**
Login is a Svelte page that POSTs JSON to an authenticate endpoint (CSRF-exempt); the
server sets the cookie and returns a redirect. One Vite build for login + admin +
account.
- *Rejected:* "Svelte admin, plain-form login" (login works without JS but two
  paradigms) — user chose the single-stack consistency, accepting that login needs JS.

## D7 — Hashing: **Reuse PBKDF2 from auth-passwords**
Copy `utils.py` verbatim. Stdlib, zero new deps, proven format.
- *Rejected:* argon2id (stronger but adds `argon2-cffi`, departs from the template).

## D8 — Persistence: **Internal DB + loud startup warning**
Store in the internal DB per requirement #1; detect the ephemeral temp-file case at
startup and warn that accounts won't persist without `--internal path.db`.
- *Rejected:* config escape hatch to a named DB (extra surface, deferred) and
  hard-refusing to start when ephemeral (breaks quick dev/test runs).

## D9 — Session token storage/expiry: **Hashed at rest + absolute expiry**
Store `sha256(token)`, sign the cookie, absolute 14-day expiry; track
`last_seen_at`/`user_agent`/`ip` for the session list.
- *Rejected:* plaintext token at rest (weaker if DB leaks) and sliding idle timeout
  (per-request writes, more logic) — the latter is an easy future add.

## D10 — Cookie & logout: **Own cookie + own logout**
Own cookie `ds_accounts_session`; own `POST /-/logout` that DELETEs the
session row and clears the cookie. Correct server-side revocation.
- *Rejected:* reusing `ds_actor` + core `/-/logout` (clears cookie only, leaves the
  session row live until expiry).

## D11 — Lifecycle ops: **Disable + delete, guarded**
create / reset-password / toggle-admin / disable (reversible, kills sessions) /
hard-delete (row + sessions) / unlock. Last-admin guard refuses to remove the final
admin (409). Password reset revokes the target's sessions.
- *Rejected:* disable-only (no hard delete) and delete-without-guard (lockout risk).

## D12 — Self-service: **Change own password + forced first change**
Users change their own password; admin-created accounts and resets set
`must_change_password`, forcing a change at next login; changing password revokes
other sessions.
- *Rejected:* change-pw without forced flow, and admin-only passwords (weak posture).

## D13 — Profile data: **Auth-only table, defer to profiles (Option 2)**
`users` holds auth fields only; display_name/email live solely in user-profiles,
captured at creation and passed through the seed hook.
- *Accepted consequence:* runtime-created accounts aren't in the directory until
  restart or first self-edit.
- *Rejected:* storing display_name/email in `users` and feeding profiles (robust but
  duplicates), and username-only (no directory data at all). User chose cleanest
  separation.

## D14 — Name: **datasette-accounts**
Kept the working-directory name. Action `datasette-accounts-admin`, cookie
`ds_accounts_session`.
- *Rejected:* `datasette-auth-accounts` and `datasette-login`.
- *Caveat noted:* "basic" can be confused with HTTP Basic auth (a different thing);
  kept anyway.

## D15 — Brute force: **Hard lockout**
5 failures → lock 15 min (both configurable); admin manual unlock; auto-unlock on
timeout; audit all attempts.
- *Accepted tradeoff:* account-keyed lockout enables a login-DoS against a known
  username. Mitigations (IP-keying, soft throttle) are future, schema-compatible.
- *Rejected:* "nothing / match auth-passwords" and "audit + soft throttle".

## D16 — `must_change_password` enforcement: **global `asgi_wrapper`, not the router**
While `must_change_password = 1` the plugin allows only the account page +
change-password endpoint, logout, and its own static/Vite assets, and
redirects/403s everything else — enforced in an `asgi_wrapper` hook that sees the
resolved actor.
- *Why:* the original spec claimed "the router refuses non-account routes", but
  the plugin's `datasette-plugin-router` only handles the plugin's own routes;
  Datasette's real surface (SQL, table/row pages, exports, other plugins) never
  passes through it, so a temporary-password user would keep full data access.
- *Rejected:* **(a) UX-only flag** (honest but weaker — a forced-change user
  retains full Datasette access until they change), and **stripping the actor in
  `actor_from_request`** (then the user isn't authenticated for the account page
  itself and `allow` blocks behave confusingly). Chose real server-side
  enforcement, matching the spec's stated intent. (Security review 2026-07-06.)

## Security review (2026-07-06) — hardening decisions
A Fable 5 pre-build review produced these binding changes (see `todos/security-review/`):
- **Login timing:** every authenticate path spends exactly one PBKDF2 verify
  (dummy hash on unknown/disabled username) except the locked-account 429 — no
  enumeration oracle. (03)
- **KDF off the event loop:** all hashing/verification via a thread executor;
  async wrappers in `passwords.py`. (03, 06)
- **Unconditional CSRF:** Content-Type + Origin/`Sec-Fetch-Site` checks in our
  own decorators, not reliance on alpha middleware. (03/04/05) — *resolves the
  CSRF open item below.*
- **`?next=` rules:** URL-decoded, reject `//`, `/\`, `\`, schemes, CR/LF; fall
  back to `/`. (03) — *resolves the `?next=` open item below.*
- **`secure_cookie` knob** for proxied TLS; **atomic** failed-attempt increment;
  **explicit `datasette.sign` namespace**; **POST-only logout** menu; **throttled**
  `last_seen_at`; **IP-trust** rule for `X-Forwarded-For`. (03/08/02)
- **Grant SQL** excludes disabled admins, shared predicate with the last-admin
  guard. (04)
- **Change-password** feeds the shared lockout counter + audit. (05/06)
- **`admin_audit` table**; **`audit_retention_days`** + expired-session purge;
  **1024-char password max**. (02/08)

## D17 — POST-only mutation endpoints + split logout path (build discovery)
`datasette-plugin-router` does **not** dispatch by HTTP method: two views on the
same path collide (first-registered wins for *all* methods) and a view registered
via `@router.POST` still runs for a `GET`. Consequences, both handled:
- Mutation decorators (`require_csrf` / `require_actor` / `require_admin`) reject
  any non-`POST` (405) and run the CSRF gates **unconditionally** — never
  treating a method as "safe/exempt". This closes a hole where a bare `GET` to a
  mutation endpoint skipped CSRF and executed the mutation.
- Logout is split across two paths: `GET /-/logout` (the confirmation page) and
  `POST /-/logout/perform` (the mutation). Same-path GET+POST is impossible here,
  and this makes the ticket-11.4 "GET must not log out" guarantee structural.
- *Discovered during M3 build; verified by test.*

## Build-time resolution of the `← verify` flags (M0–M5, datasette 1.0a35)
- **`sign`/`unsign` signature:** `datasette.sign(value, namespace='default')` —
  explicit namespace `"datasette-accounts"` used (ticket 11.3). ✅
- **Admin self-answer mechanism:** global actions resolve via
  `permission_resources_sql` returning a `PermissionSQL` whose SQL runs against
  the internal DB (where `users` lives). Must include `actor_id` in `params` or
  core drops the binding. Root and enabled-admin both allowed in one statement. ✅
- **`asgi_wrapper` actor visibility:** resolved by **not** depending on it — the
  wrapper calls the same `resolve_actor(datasette, request)` helper as
  `actor_from_request`, reading our own session cookie (ticket 03 / D16). ✅
- **Forwarded headers:** the pinned core does not rewrite `request.scheme` for us,
  so `secure_cookie: auto` and the IP-trust rule gate `X-Forwarded-*` behind a new
  `trust_proxy_headers` config flag (default false). ✅
- **`vite_entry` signature:** `(datasette, plugin_package, manifest_dir=None)` —
  no `vite_dev_path` kwarg in the pinned `datasette-vite`. ✅
- Still open for M7: confirm `base_url` sub-path handling for `?next=` and the
  Vite dev/HMR wiring under the pinned `datasette-vite`.

## Open action items (carry into build)
- **CSRF/cross-origin:** ✅ *resolved* — our decorators enforce Content-Type +
  Origin/`Sec-Fetch-Site` unconditionally (D-security above / 03). Remaining
  action is defense-in-depth only: confirm core's cross-origin middleware is also
  active in the pinned version (we do not depend on it).
- **Alpha versions:** ✅ *resolved* — built against `datasette==1.0a35`,
  `datasette-plugin-router` (Router/Body/PermissionSQL), `datasette-vite`
  (`vite_entry(datasette, plugin_package, manifest_dir=None)`).
- **`?next=` validation:** ✅ *resolved* — concrete accept/reject rules specified
  in [`03-authentication.md`](03-authentication.md) and implemented in
  `security.validate_next` (uses `datasette.setting("base_url")`).
- ← *verify-during-build* flags all resolved (see the resolution list above),
  except the frontend Vite dev/HMR wiring, which is exercised via
  `just dev-with-hmr` / `DATASETTE_AUTH_BASIC_LOGIN_VITE_PATH` but not automated.
