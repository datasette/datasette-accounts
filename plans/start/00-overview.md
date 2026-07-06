# 00 — Overview

## What we're building

A Datasette plugin, **`datasette-auth-basic-login`**, that provides username/password
authentication where **accounts live in Datasette's internal database** (not in
plugin config, unlike `datasette-auth-passwords`). It adds:

1. **Database-backed accounts** — create/manage login users at runtime, persisted in
   the internal DB.
2. **An admin permission** — a registered Datasette 1.0 *action*
   (`datasette-auth-basic-login-admin`) that lets an admin provision new accounts,
   revoke access, reset passwords, and toggle who else is an admin.
3. **A Svelte/Vite/TS frontend** built per `datasette-alex-fullstack-skill` — a login
   page, an admin dashboard, and a self-service account page.

## Scope boundary (important)

This plugin owns **identity**: accounts, passwords, sessions, and a single
`is_admin` flag. It does **not** own resource-level authorization (who can see which
database/table). That is delegated to `datasette-acl` or Datasette's config
`allow` blocks, which consume the actor and id this plugin emits. See
[`09-decisions-log.md`](09-decisions-log.md) D1.

## Key properties

- **Server-side sessions** (revocable) rather than a stateless signed actor cookie.
  Revoking an account or a session takes effect on the *next request*.
- **Instant revocation** — `actor_from_request` re-checks the session + account on
  every request; disabling an account or deleting a session logs the user out
  immediately.
- **Persistence-aware** — accounts are stored in the internal DB, which is ephemeral
  unless the operator passes `--internal path.db`; we warn loudly at startup when it
  is ephemeral.
- **Compatible with `datasette-user-profiles`** — we emit a stable actor `id` and
  seed the profile directory; profiles owns display_name/email.
- **Bootstraps via `datasette --root`** — no chicken-and-egg, no secrets in config.

## The actor we emit

```json
{ "id": "<ULID>", "username": "alice", "is_admin": true }
```

`id` is an immutable ULID and is the permanent join key to user-profiles and to any
acl grants. `username` is a mutable login credential.
