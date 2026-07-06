# 08 — Plugin configuration

Config lives under the `datasette-auth-basic-login` plugin block in Datasette
metadata/config. All options have safe defaults; a zero-config install works (it just
warns about persistence).

| option | type | default | meaning |
|--------|------|---------|---------|
| `session_ttl_days` | int | `14` | absolute session lifetime |
| `password_min_length` | int | `8` | minimum new-password length (no complexity rule) |
| `lockout_threshold` | int | `5` | consecutive failures before lock; `0` disables lockout |
| `lockout_minutes` | int | `15` | auto-unlock window after a lock |
| `secure_cookie` | `"auto"` \| `true` \| `false` | `"auto"` | Secure attribute on the session cookie. `auto` = Secure when the request is HTTPS or a trusted proxy forwards `X-Forwarded-Proto: https`. **Set `true` for any proxied production deployment** (TLS terminated at nginx/Caddy/fly/Cloud Run makes Datasette see plain HTTP, so `auto` alone may never mark it Secure). See [`03-authentication.md`](03-authentication.md) |
| `audit_retention_days` | int | `90` | delete `login_audit` rows older than this on startup + after login; `0` = keep forever. Retention is the mitigation for sensitive typos landing in `login_audit.username` — see [`02-data-model.md`](02-data-model.md) |

## Example

```yaml
plugins:
  datasette-auth-basic-login:
    session_ttl_days: 30
    password_min_length: 12
    lockout_threshold: 8
    lockout_minutes: 30
    secure_cookie: true        # recommended behind a TLS-terminating proxy
    audit_retention_days: 30
```

## Recommended companion config

To keep this plugin authoritative for auth while letting user-profiles own the
directory, operators may lock profile fields they consider auth-owned (optional):

```yaml
plugins:
  datasette-user-profiles:
    editable_fields:
      email: false        # if email is managed elsewhere
```

## Persistence reminder (not a config option)

Accounts persist only when Datasette runs with `--internal path.db`. Without it the
internal DB is a temp file wiped on exit; the plugin logs a prominent startup warning
in that case. This is intentionally not a plugin config key — it is a Datasette CLI
flag.

## Deliberately NOT config (v1)

- Password hashing parameters (fixed at the auth-passwords defaults: PBKDF2, 480k).
- **Password maximum length** — fixed at 1024 chars (an unbounded KDF input is a
  needless DoS vector; see [`03-authentication.md`](03-authentication.md)).
- Cookie name / attributes (except the `secure_cookie` knob above).
- Whether to store accounts in a named DB instead of the internal DB (the
  secrets/auth-tokens "escape hatch" was considered and dropped for v1 — see D8).
