# 02 — Data model

All tables live in the **internal database** (`datasette.get_internal_database()`),
created idempotently in the `startup` hook via `sqlite-migrate`, migration namespace
`datasette-accounts.internal`. Append-only migrations (`m001_…`, `m002_…`);
never edit a shipped migration.

No name collision with `datasette-user-profiles` (`datasette_user_profiles`,
`datasette_user_profile_photos`). **Actual table names carry the plugin prefix**
(the internal DB is shared): `users` → `datasette_accounts_users`,
`sessions` → `datasette_accounts_sessions`, `login_audit` →
`datasette_accounts_login_audit`, `admin_audit` →
`datasette_accounts_admin_audit`. This doc uses the short names for
readability; `db.py` defines the prefixed constants.

## `users`

Auth fields **only** — display_name/email are NOT stored here; they belong to
user-profiles (see [`07-user-profiles-compat.md`](07-user-profiles-compat.md)).

| column | type | notes |
|--------|------|-------|
| `id` | TEXT PK | ULID, immutable, == actor `id` and profiles `actor_id` |
| `username` | TEXT UNIQUE | login credential, mutable |
| `password_hash` | TEXT | `pbkdf2_sha256$iterations$salt$b64hash` |
| `is_admin` | INTEGER | 0/1 |
| `disabled` | INTEGER | 0/1; reversible "revoke access" |
| `must_change_password` | INTEGER | 0/1; forces change at next login |
| `failed_attempts` | INTEGER | consecutive failed logins, reset on success |
| `locked_until` | TEXT NULL | ISO timestamp; login refused while in the future |
| `created_at` | TEXT | ISO |
| `updated_at` | TEXT | ISO |

## `sessions`

Server-side sessions. The raw token exists only in the user's cookie; the table
stores only its SHA-256 (a DB read leak cannot resurrect a live session).

| column | type | notes |
|--------|------|-------|
| `token_sha256` | TEXT PK | `sha256(raw_token)` |
| `actor_id` | TEXT | FK-ish → `users.id` |
| `created_at` | TEXT | ISO |
| `expires_at` | TEXT | ISO; absolute expiry = created + `session_ttl_days` |
| `last_seen_at` | TEXT | updated per request, **throttled** (see [`03`](03-authentication.md)); for admin session list |
| `user_agent` | TEXT NULL | for the admin session list |
| `ip` | TEXT NULL | recorded per the IP-trust rule below; for the admin session list |

Index on `actor_id` for "list/revoke sessions for a user" and "log out everywhere".

Revocation:
- one device → `DELETE WHERE token_sha256 = ?`
- all devices for a user → `DELETE WHERE actor_id = ?`
- account disabled/deleted → delete all that actor's rows

**Expired-session purge (bounded growth).** The per-lookup lazy delete in
[`03-authentication.md`](03-authentication.md) only reaps a token when *that
token* is presented again; sessions abandoned without logout (cleared browser,
lost device) would otherwise live until the process forgets them. So also run
`DELETE FROM sessions WHERE expires_at <= now` on `startup` and
opportunistically after each successful login — both hooks already hold the
internal DB's write connection, so **no background scheduler / timer thread**.
Keep the lazy per-lookup delete too.

## IP-trust rule (`sessions.ip`, `login_audit.ip`)

Record the **socket peer address** by default. Use `X-Forwarded-For` (first
untrusted hop) **only** when the operator has declared a trusting proxy — reuse
the same proxy signal as `secure_cookie: auto` ([`03`](03-authentication.md) /
[`08`](08-config.md)). Otherwise the audit trail and any future IP-keyed lockout
([`06-brute-force.md`](06-brute-force.md)) are attacker-spoofable via a forged
`X-Forwarded-For`.

## `login_audit`

Failed/successful login history — feeds the lockout counter and gives admins
visibility. Also receives **change-password** current-password verification
attempts (they share the login lockout counter — see
[`05-self-service.md`](05-self-service.md) / [`08-brute-force`](06-brute-force.md));
for those rows `username` is the actor's own username.

| column | type | notes |
|--------|------|-------|
| `id` | INTEGER PK | autoincrement |
| `username` | TEXT | as submitted (may not match a real account). **May contain sensitive typos** — passwords accidentally typed into the username field are recorded verbatim; `audit_retention_days` is the mitigation |
| `ip` | TEXT NULL | per the IP-trust rule above |
| `timestamp` | TEXT | ISO |
| `success` | INTEGER | 0/1 |

**Bounded growth (retention).** Every attempt — including failures from
unauthenticated attackers — inserts a row, so an attacker could otherwise grow
the internal DB without bound (disk-fill DoS). New config option
`audit_retention_days` (int, default `90`; `0` = keep forever, see
[`08-config.md`](08-config.md)). On `startup` and opportunistically after each
successful login, `DELETE FROM login_audit WHERE timestamp < now - retention`.
Same hooks as the session purge — no background thread.

## `admin_audit`

Records consequential **admin mutations** and self-service password changes.
Login history lives in `login_audit`; this table answers "who made this account
an admin and when" / "who reset that password before the incident". Audit
history cannot be retrofitted for events that already happened, so it ships in
v1.

| column | type | notes |
|--------|------|-------|
| `id` | INTEGER PK | autoincrement |
| `timestamp` | TEXT | ISO |
| `operation` | TEXT | `create`, `reset-password`, `toggle-admin`, `disable`, `enable`, `delete`, `unlock`, `revoke-session`, `logout-everywhere`, `change-own-password` |
| `actor_id` | TEXT | who performed it (`"root"` for the bootstrap root actor) |
| `target_id` | TEXT | affected `users.id` |
| `detail` | TEXT NULL | small JSON, e.g. `{"is_admin": true}` for toggles |

- **Never** store passwords / hashes / tokens in `detail`.
- Every admin mutation handler ([`04-admin-and-permissions.md`](04-admin-and-permissions.md))
  writes exactly one row **inside the same transaction as the mutation**.
  Self-service password change ([`05-self-service.md`](05-self-service.md))
  writes `operation = "change-own-password"` with `actor_id == target_id`.
- Growth is bounded by admin activity (unlike `login_audit`) — **no pruning
  needed**.

## Notes

- Timestamps stored as ISO-8601 text. **`Date.now()`/`datetime.now()` are fine in
  the plugin at runtime** — the "no clock" restriction only applies to Workflow
  scripts, not to the plugin code.
- `locked_until` + `failed_attempts` live on the `users` row (cheap to check during
  login); `login_audit` is the historical record.
