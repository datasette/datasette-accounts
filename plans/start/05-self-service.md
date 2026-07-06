# 05 — Self-service (non-admin users)

Logged-in users manage their own credential at a Svelte page **`/-/account`**.

## Change own password

```
POST /-/account/api/change-password  { current_password, new_password }
  1. require an authenticated actor (any user); inherits the unconditional CSRF
     gates (Content-Type + Origin/Sec-Fetch-Site) from the shared decorators
  2. if account locked (locked_until > now): 429   # shared login lockout, see below
  3. ok = await averify_password(current_password, actor.password_hash)   # off-loop
     audit the attempt in login_audit(username=actor.username, ip, success=ok)
     if not ok:
        UPDATE users SET failed_attempts = failed_attempts + 1 WHERE id = ?   # atomic
        if new_failed_attempts >= lockout_threshold: locked_until = now + lockout_minutes
        return 401 (generic)
  4. enforce password_min_length (default 8) and the fixed 1024-char max
     (see 03-authentication.md)
  5. set new password_hash (await ahash_password), must_change_password = 0,
     updated_at = now; reset failed_attempts = 0, locked_until = NULL
  6. revoke the user's OTHER sessions (keep the current one):
       DELETE FROM sessions WHERE actor_id = ? AND token_sha256 != sha256(current_token)
  7. write admin_audit(operation="change-own-password", actor_id == target_id)
  8. return { ok: true }
```

### Brute-force protection on `current_password`

Failed `current_password` verifications route through the **same** counter and
lock as login (`users.failed_attempts` / `users.locked_until`,
[`06-brute-force.md`](06-brute-force.md)) and are recorded in `login_audit`.
Without this, an attacker holding a live session (hijacked cookie, unattended
browser) could brute-force the current password at full speed — with no limit
and no audit trail — escalating "has a session" into "knows the password" (which
survives session revocation and may be reused elsewhere). A lock set here also
blocks login, and a successful change resets the counter. These verifications
also run off the event loop (ticket-02 rule).

## Forced first change

- Admin-created accounts and admin password-resets set `must_change_password = 1`.
- On successful login the authenticate response signals `must_change_password`; the
  frontend routes the user to `/-/account` and blocks navigation until changed.
- **Server-side enforcement — global `asgi_wrapper` (decision D16).** The plugin's
  `datasette-plugin-router` instance only handles *this plugin's own* routes
  (`/-/login`, `/-/admin/…`, `/-/account/…`); Datasette's real surface — SQL
  queries, table/row pages, exports, other plugins' routes — never passes
  through it. So gating "in the router" would gate almost nothing and a user
  holding a temporary password would keep full data access. Enforcement is
  therefore an **`asgi_wrapper`** hook: when the resolved actor has
  `must_change_password = 1`, allow only the account page + its change-password
  endpoint, logout, and this plugin's static/Vite assets, and **redirect (HTML)
  or 403 (JSON) everything else**. Access is restored the moment the flag clears.

  Implementation notes for the build:
  - The wrapper needs the resolved actor. ← **verify** in the pinned Datasette
    that `asgi_wrapper` runs after / independently of `actor_from_request` and
    can see the actor (scope `"actor"` availability differs across versions). If
    it can't, have `actor_from_request` stash a marker (e.g. on `scope`) that the
    wrapper reads.
  - Do **not** implement this by stripping the actor in `actor_from_request` —
    the user would then be unauthenticated for the account page itself and
    config `allow` blocks would behave confusingly.
  - The frontend redirect to `/-/account` remains as the friendly UX layer; the
    wrapper is the actual guarantee, so skipping the frontend can't bypass it.

## Profile fields

display_name/email/bio/avatar are edited through **datasette-user-profiles'** own
self-service UI (`/-/user-profile/edit`), not this plugin. We only originate the
initial values at account creation via the seed hook. See
[`07-user-profiles-compat.md`](07-user-profiles-compat.md).

## Out of scope for v1

- Self-service username change (usernames are admin-managed for now; the id is what's
  immutable, so this is an easy future addition).
- Password-reset-by-email / forgot-password flow (no mail dependency in v1).
