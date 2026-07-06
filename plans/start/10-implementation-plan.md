# 10 — Implementation plan

Build order is chosen so each milestone is independently testable, backend-first
(the frontend depends on the JSON API + page-data contracts).

## Build status (2026-07-06)

| Milestone | Status |
|-----------|--------|
| M0 Scaffold | ✅ built (pyproject, package, Justfile, CLAUDE.md, LICENSE) |
| M1 Internal DB + migrations | ✅ built + tested (4 tables, ephemeral warning, purge) |
| M2 Passwords + sessions | ✅ built + tested (async KDF wrappers, DUMMY_HASH, hash-password CLI) |
| M3 Authentication | ✅ built + tested (login/logout/actor, lockout, `?next=`, CSRF, timing) |
| M4 Admin action + API | ✅ built + tested (self-answer grant, last-admin guard, audit) |
| M5 Self-service + forced change | ✅ built + tested (change-pw lockout, asgi_wrapper gate) |
| M6 user-profiles seeding | ⬜ pending |
| M7 Frontend (Svelte/Vite) | ⬜ pending — `routes/pages.py` ships minimal server-rendered HTML shells in the interim |
| M8 Docs + polish | ⬜ pending |

**21 tests green** (`uv run pytest`). Full bootstrap→admin→forced-change→disable
flow verified end-to-end against an in-process Datasette 1.0a35. Build-time
discoveries and resolved `← verify` flags are recorded in
[`09-decisions-log.md`](09-decisions-log.md) (D17 + the resolution list).

## M0 — Scaffold
- `pyproject.toml` (deps from [`01-architecture.md`](01-architecture.md)), entry point
  `auth_basic_login`, package-data for `static/**`, `templates/*`, `manifest.json`.
- `Justfile`, `CLAUDE.md` (+ `AGENTS.md` symlink), `LICENSE` (Apache-2.0), `README.md`.
- `frontend/` skeleton per the fullstack skill (vite.config, tsconfig, package.json,
  `store.svelte.ts`, `load.ts`). Ports 8006 / 5180.
- `just types && just frontend && uv sync` succeed; empty plugin loads in Datasette.

## M1 — Internal DB + migrations
- `internal_migrations.py` (`users`, `sessions`, `login_audit`, **`admin_audit`**),
  namespace `datasette-auth-basic-login.internal`.
- `startup` hook applies migrations; logs the **ephemeral-internal-DB warning**;
  runs the startup **expired-session purge** and **`login_audit` retention delete**
  (no background thread — see [`02-data-model.md`](02-data-model.md)).
- `internal_db.py` read/write helpers.
- *Test:* startup creates tables (incl. `admin_audit`) idempotently; warning fires
  only for temp internal DB; back-dated `login_audit` rows and expired `sessions`
  are purged on startup while fresh rows remain; `audit_retention_days: 0` keeps
  everything.

## M2 — Passwords + sessions core
- `passwords.py` copied from auth-passwords, **plus async wrappers**
  (`averify_password`, `ahash_password`) that run the sync KDF via
  `asyncio.to_thread`; handlers use only the async wrappers. Module-level
  `DUMMY_HASH` constant. Enforce `password_min_length` + fixed **1024-char max**.
- `sessions.py`: mint / `sha256` / insert / lookup / revoke-one / revoke-all /
  expire / **bulk-purge-expired**. Cookie sign/unsign use the explicit
  `"datasette-auth-basic-login"` namespace.
- `register_commands` → `datasette hash-password`.
- *Test:* async wrappers return identical results to the sync functions;
  `verify_password` matches; expired/revoked lookups return nothing; 1025-char
  password rejected; cookie signed under the namespace round-trips while a
  default-namespace `unsign` fails.

## M3 — Authentication (`actor_from_request`, login, logout)
- `actor_from_request` per the flow in [`03-authentication.md`](03-authentication.md),
  incl. the throttled `last_seen_at` write (>60 s) and lazy expired-row delete.
- `POST /-/login/api/authenticate`: dummy-hash verify on unknown/disabled username
  (exactly one PBKDF2 per path except the locked 429), **atomic** failed-attempt
  increment, lockout, `?next=` validation, mint session, set cookie with the
  `secure_cookie` logic, opportunistic session/audit purge.
- `POST /-/logout` (delete session row, clear cookie) + the GET POST-form page for
  the menu link.
- Unconditional **CSRF decorators** (Content-Type + Origin/`Sec-Fetch-Site`).
- `menu_links` (Log in / Log out-via-POST-form).
- *Test (in-process `Datasette` + `ds.client`):* login sets cookie; authed request
  gets the actor; logout kills the session; **GET on `/-/logout` does not destroy
  the session**; disabled account → no actor next request; bad password increments
  failures (two near-concurrent failures increment by 2); lockout at threshold
  returns 429.
  - **Enumeration:** unknown-username and wrong-password responses are both a
    generic 401 with identical bodies; a monkeypatched counter shows the
    unknown-username path calls `verify_password` exactly once (test the call, not
    wall-clock latency).
  - **`?next=`** table-driven: `//evil.com`, `/\evil.com`, `https://evil.com`,
    `javascript:alert(1)`, `%2F%2Fevil.com`, `/ok/path?x=1` — only the last passes;
    all others redirect to `/`.
  - **Cookie attrs:** plain http → no Secure; `secure_cookie: true` → Secure;
    simulated `X-Forwarded-Proto: https` → Secure; always `HttpOnly`,
    `SameSite=Lax`, `Path=/`.
  - **CSRF:** POST with `Content-Type: text/plain` / form-encoded body → rejected;
    cross-site `Origin` / `Sec-Fetch-Site: cross-site` → rejected; no browser
    headers (curl-style) → allowed.

## M4 — Admin action + gate + management API
- `register_actions` + `permission_resources_sql` self-answer
  (`root OR (is_admin = 1 AND disabled = 0)`) — one **shared SQL predicate** with
  the last-admin guard.
- `@require_admin` decorator on the router (inherits the CSRF gates).
- JSON API `/-/admin/api/…`: create, reset-password, toggle-admin, disable, enable,
  delete, unlock, list-sessions, revoke-session, logout-everywhere — each writes an
  **`admin_audit`** row in the same transaction.
- **Last-admin guard** (synchronous count-then-write, 409), counting with the
  shared predicate.
- *Test:* non-admin → 403; root → allowed; is_admin user → allowed; **a disabled
  admin is denied even when the actor dict is forged with `is_admin: true`** (grant
  derives from the DB row, not the actor dict); last-admin guard blocks
  disable/delete/demote; reset-password revokes target sessions; disable kills
  sessions; **each mutation writes a matching `admin_audit` row** (operation,
  actor_id, target_id).

## M5 — Self-service API + forced change
- `POST /-/account/api/change-password` (verify current **off-loop + shared lockout
  counter + `login_audit`**, revoke other sessions, clear `must_change_password`,
  write `admin_audit` `change-own-password`).
- Server-side `must_change_password` gate via **`asgi_wrapper`** (decision D16) —
  allows only account/change-password/logout/assets, redirects/403s the rest.
- *Test:* wrong current → 401; success rotates hash + revokes other sessions;
  **N wrong `current_password` attempts → 429 lock; that lock also blocks login
  (shared counter); success resets it; attempts appear in `login_audit`**; a user
  with `must_change_password=1` is redirected/403'd on a core route (e.g. `/`), can
  still reach `/-/account` + change-password + logout, and regains full access
  after changing.

## M6 — user-profiles seeding
- `datasette_user_profile_seeds` hookimpl emitting `ProfileSeed(actor_id, display_name,
  email)`; guard import so the plugin works when user-profiles is absent.
- *Test:* with user-profiles installed, startup seeds directory rows fill-missing.

## M7 — Frontend (Svelte/Vite/TS)
- `page_data.py` Pydantic models + `scripts/typegen-pagedata.py`; `just types`.
- Pages: `login`, `admin` (user table + per-user session drawer), `account`.
- `openapi-fetch` client wired to the M3–M5 endpoints; `#pageData` bootstrap.
- Base template `basic_login_base.html` + `vite_entry`.
- *Manual verify:* full flow through the browser via the `/run` skill — root →
  create admin → log in as admin → create user (must-change) → user logs in, forced
  change → admin disables user → user logged out → admin lists/revokes sessions.

## M8 — Docs + polish
- README (install, `--root` bootstrap, `--internal` persistence, config table incl.
  **`secure_cookie` / `audit_retention_days`** and the "set `secure_cookie: true`
  behind a TLS-terminating proxy" note, demo walkthrough).
- Resolve the remaining open action items in
  [`09-decisions-log.md`](09-decisions-log.md): confirm alpha versions, and the
  `← verify-during-build` flags (forwarded-header handling, `sign`/`unsign`
  signature, `base_url` exposure, `asgi_wrapper` actor visibility). CSRF and
  `?next=` items are already resolved in the spec.

## Testing conventions
- `pytest` + `pytest-asyncio` (`asyncio_mode = strict`), in-process
  `Datasette(memory=True, ...)` driven via `ds.client` (as auth-passwords does), plus
  an `--internal` temp-file variant for persistence tests.
- CSRF-exempt JSON posts in tests; decode the session cookie with `datasette.unsign`.

## Definition of done (v1)
All of M0–M8 green; the M7 manual flow verified end-to-end; zero-config install loads
and warns about persistence; works with and without user-profiles installed.
