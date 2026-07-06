# 04 — Admin permission & management UI

## The admin action

Register a Datasette 1.0 **action** via `register_actions`:

```python
Action(
    name="datasette-auth-basic-login-admin",
    description="Manage datasette-auth-basic-login accounts",
)
```

**Self-answer** it so it is true when the actor is `root` OR their `users` row has
`is_admin = 1` **and is not disabled**. In the 1.0 API this is done with a
`permission_resources_sql` hook contributing an allow-SQL that selects the admin
actors (root handled by core's `root_enabled` allow, plus our

```sql
SELECT id FROM users WHERE is_admin = 1 AND disabled = 0
```

). The `disabled = 0` filter matters: the grant SQL is UNIONed into Datasette's
permission system and consumed by introspection and by *other* actor sources, so
a disabled account whose `id` is reproduced by some other plugin/mechanism must
not receive admin rights from its stale `users` row. **Single source of truth:**
this predicate (`is_admin = 1 AND disabled = 0`) is exactly the one the
last-admin guard counts (below) — implement both from one shared SQL
fragment/constant so the two definitions of "admin" can never drift.

Because Datasette UNIONs permission providers, `datasette-acl` or config `allow`
blocks can *also* grant this action to other actors, and it shows up in
permission introspection.

Every management route checks:

```python
if not await datasette.allowed(action="datasette-auth-basic-login-admin", actor=request.actor):
    raise Forbidden(...)
```

Encapsulated in a `@require_admin` decorator on the shared `Router` (mirrors
`datasette-user-profiles`' `@check_permission()`).

## Bootstrap (first admin)

Operator runs `datasette --root data.db --internal accounts.db`. Datasette prints a
one-time `/-/auth-token?token=…` URL that logs them in as `{"id": "root"}`. Root is
always an admin (core allows root everything when `root_enabled`), so root opens
`/-/admin/users`, creates the first real admin account, then stops using `--root`.
Root is never a row in our `users` table.

Alternative for headless setups: the `datasette hash-password` CLI plus a future
`create-admin` command (not in v1) could insert an admin row directly.

## Admin UI — Svelte SPA at `/-/admin/users`

Page shell served by a GET route (gated by `@require_admin`); data + mutations via
JSON API (also gated). Uses the fullstack skill's type-safe pipelines (Pydantic →
page-data types, OpenAPI → `openapi-fetch` client).

All mutation endpoints are JSON `POST`s and inherit the **unconditional CSRF
gates** (Content-Type + Origin/`Sec-Fetch-Site`) from the shared router
decorators — see [`03-authentication.md`](03-authentication.md). Each mutation
also writes exactly one `admin_audit` row **inside the same transaction** as the
mutation (see [`02-data-model.md`](02-data-model.md)): `operation`, `actor_id`
(the acting admin, `"root"` for the bootstrap actor), `target_id`, and a small
no-secrets `detail` JSON (e.g. `{"is_admin": true}` on toggle). Never put
passwords/hashes/tokens in `detail`.

### Operations (JSON API under `/-/admin/api/…`)

| Operation | Effect |
|-----------|--------|
| **create** | insert `users` row (ULID id); optional display_name/email → seed profiles; may set `is_admin`, `must_change_password=1`; set initial password |
| **reset-password** | set new `password_hash`, `must_change_password=1`, and **revoke that user's sessions** |
| **toggle-admin** | flip `is_admin` |
| **disable** | `disabled=1` + delete all that user's sessions (reversible "revoke access") |
| **enable** | `disabled=0` |
| **delete** | delete `users` row + all their sessions (hard delete) |
| **unlock** | clear `locked_until` + `failed_attempts` |
| **list sessions** | rows from `sessions` for a user (ua, ip, last_seen) |
| **revoke session** | delete one `sessions` row |
| **log out everywhere** | delete all `sessions` rows for a user |

### Last-admin guard

Refuse any operation that would leave **zero** enabled admins — i.e. disabling,
deleting, or demoting (`toggle-admin` off) the final admin. "Enabled admin" is
counted with the **same predicate as the grant SQL** (`is_admin = 1 AND
disabled = 0`, from one shared fragment) so the guard and the grant can't drift.
Enforced **synchronously on the write connection** (count-then-write in one
transaction, like `datasette-acl`'s `_guard_last_manager_sync`) to avoid a race,
surfaced as HTTP 409.

Note: `root` does not count as an admin for this guard (root is a bootstrap escape
hatch, may be disabled in production), so the guard protects real DB admins.

### Deleting an account & user-profiles

Hard delete removes the `users` row and sessions. It leaves the user-profiles
directory row (`datasette_user_profiles`) as a harmless orphan — we do **not** write
to profiles' tables directly. Purging it is deferred (would require a profiles-side
hook or accepted schema coupling).

### Menu integration

`menu_links` adds an "Accounts" link to the Datasette menu only when
`datasette.allowed(action="datasette-auth-basic-login-admin", actor)` is true.
