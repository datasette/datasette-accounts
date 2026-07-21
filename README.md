# datasette-accounts

> [!WARNING]
> This plugin is experimental!


Username/password authentication for [Datasette](https://datasette.io) with
**accounts stored in the internal database** (not in plugin config). Provisioning,
password resets, disabling, and admin management all happen at runtime through an
admin UI, a `datasette accounts` CLI, and a JSON API, guarded by a real Datasette
1.0 permission.

> **"Basic" as in database-backed basic login — not HTTP Basic auth.**

Users log in at `/-/login`:

![The login page: a Log in heading with username and password fields, and a help note reading "Trouble signing in? Email data-help@example.com."](docs/screenshots/login.png)

Admins manage accounts at `/-/admin/users` — create accounts and disable, lock,
reset, promote, or delete existing ones:

![The admin accounts table listing users with admin, status, and lock columns and per-user action buttons.](docs/screenshots/admin.png)

## Features

- **Database-backed accounts** in Datasette's internal DB (create / disable /
  delete / reset-password / toggle-admin / unlock at runtime).
- **Server-side sessions** — revocable per-device, with "log out everywhere" and
  an admin session list. Disabling an account or revoking a session takes effect
  on the next request.
- **A registered admin action** (`datasette-accounts-admin`) that is
  self-answered for `root` and enabled admins, and composes with config `allow`
  blocks.
- **A `datasette accounts` CLI** for provisioning and managing accounts from the
  shell — the same audited, guarded code path as the web admin UI.
- **Security hardening** built in: timing-safe login (no username enumeration),
  PBKDF2 run off the event loop, unconditional CSRF gates, strict `?next=`
  validation, brute-force lockout (shared by login and change-password), forced
  first-password-change, audit logging, and retention/pruning.
- **A Svelte/TS frontend** for the login, account, and admin pages.
- **Integrates with `datasette-user-profiles`** (a required dependency) — emits a
  stable actor `id` and seeds the profiles directory, so every account can view
  and edit their profile once granted the `profile_access` permission.

## Installation

```bash
datasette install datasette-accounts
```

Requires Datasette **1.0a23+** and Python 3.10+.

## Getting started

### 1. Persist accounts with `--internal`

Accounts live in the internal database, which is an **ephemeral temp file unless
you pass `--internal`**. The plugin prints a loud startup warning when it is
ephemeral. For any real use:

```bash
datasette mydata.db --internal accounts.db
```

### 2. Create the first admin

There is no admin until you make one. The quickest way is the CLI, which writes
directly to the internal database — point it at the same `accounts.db`:

```bash
datasette accounts bootstrap-admin alice --generate -i accounts.db
# Created admin alice.
# Password (shown once): …
```

`bootstrap-admin` is **idempotent** — if an enabled admin already exists it prints
`admin already exists — skipping` and exits `0`, so it is safe to drop into a
container entrypoint or provisioning script. Pass `--password-stdin` to feed a
password without exposing it in argv, or `--generate` to mint one.

Prefer to bootstrap from the browser? Start Datasette with `--root`:

```bash
datasette mydata.db --internal accounts.db --root
```

Datasette prints a one-time `http://…/-/auth-token?token=…` URL that logs you in
as `root`, who is always allowed the admin action. Open **`/-/admin/users`**,
create your first admin account, then restart without `--root`.

### 3. Day-to-day

- Users log in at **`/-/login`** and manage their own password at **`/-/account`**.
- Admins manage accounts at **`/-/admin/users`**.
- The Datasette menu gains **Log in** / **Log out** / **Your account** entries,
  and an **Admin** link for admins.

## Managing accounts from the shell

The `datasette accounts` command group is the CLI counterpart to the admin UI. It
does not touch the internal tables directly — every command reconstructs a
Datasette instance and calls the same audited, guarded `db.*` functions the web
routes use, so last-admin guards, session revocation, and the audit trail all
apply identically. Every mutating command requires `-i/--internal PATH`
(a persistent DB); every data-emitting command supports `--json`.

```
datasette accounts create USERNAME       # --admin, --generate, --password-stdin, --must-change
datasette accounts invite USERNAME        # create + one-time invite link (--admin, --ttl-hours, --base-url)
datasette accounts bootstrap-admin NAME   # idempotent first-admin creation
datasette accounts list                   # --admins / --pending / --locked / --disabled / --expired / --awaiting-approval
datasette accounts approve USERNAME       # approve a self-registered account request
datasette accounts reject USERNAME        # reject (delete) a pending account request
datasette accounts reset-password USERNAME
datasette accounts reset-link USERNAME    # one-time password-reset link (--ttl-hours, --base-url)
datasette accounts expire USERNAME        # set/clear an expiry deadline (--at, --in-days, --clear)
datasette accounts promote / demote USERNAME
datasette accounts disable / enable USERNAME
datasette accounts unlock USERNAME        # clear lockout counters
datasette accounts logout USERNAME        # revoke all of a user's sessions
datasette accounts delete USERNAME --yes
datasette accounts registration on|off|status  # open/close self-registration (runtime toggle)
datasette accounts providers              # list installed sign-in providers + their state
datasette accounts enable-provider KEY    # break-glass: turn a sign-in provider on
datasette accounts disable-provider KEY   # turn one off (refuses the last enabled provider)
datasette accounts set-signups KEY off|approval|auto  # first-contact policy per provider
datasette accounts audit                  # the admin-audit trail
datasette accounts login-attempts         # the login-attempt audit
datasette accounts hash-password [PASSWORD]
```

Run `datasette accounts COMMAND --help` for the full options of each. Generated
passwords are printed once to stdout and never written to the audit trail or
logs.

## Messages

Admins can write optional help text under **`/-/admin/config`** — a sign-in prompt
shown on the homepage to signed-out visitors, and a help/contact note shown below
the login form. Blank hides a message. Bodies are admin-authored HTML rendered
verbatim, so you can include links and `mailto:` contacts (only admins can edit
them). The same page holds the self-registration toggle.

## Sign-in providers

The username/password login is the built-in **provider**. Other packages can add
sign-in methods (GitHub, Google/OIDC, Discord, …) through the
`datasette_accounts_auth_providers` hookspec, and every provider inherits the
same account semantics: the disable/expire/pending gates, the shared approval
queue and abuse caps, the session list, and the audit trail. A provider only
proves control of an external identity — datasette-accounts owns identity,
policy, and sessions. External identities map to accounts **only** by the IdP's
stable subject id (never by email).

### For admins

Installing a provider package changes nothing until you enable it — external
providers are **disabled by default**. From the **Configuration** admin page
(`/-/admin/config`) or the CLI:

```bash
datasette accounts providers -i accounts.db                 # list + state
datasette accounts enable-provider github -i accounts.db    # turn it on
datasette accounts set-signups github approval -i accounts.db  # off | approval | auto
```

Each provider has two runtime settings: **enabled** (on/off) and **signups**
(`off` = only already-linked accounts may sign in; `approval` = first-time
identities land in the approval queue; `auto` = first-time identities are
activated immediately — for trusted IdPs only). Users link and unlink providers
to their own account from `/-/account`, gated by fresh proof of an existing
sign-in method.

`enable-provider` is the **break-glass**: it works with only disk access and no
web session, so a locked-out operator can always restore password login even
after disabling every other provider. `disable-provider` refuses to disable the
last enabled provider (the same guard applies in the UI).

### For provider authors

See [`examples/datasette-accounts-demo-auth`](examples/datasette-accounts-demo-auth/) —
a tiny, installable demo provider whose README doubles as the provider-author
tutorial (the hookspec contract, what core does for you, and a security
checklist). It is development-only and deliberately insecure — sign-in is a
subject plus a plaintext 4-digit PIN, claimed on first use — so it exercises the
whole external path (a real verification step, provider-owned storage, an actual
UI) without needing any external accounts; copy it as scaffolding for a real
OAuth/OIDC provider. For real-world, non-toy examples see
the `datasette-accounts-github`, `datasette-accounts-discord`, and
`datasette-accounts-bluesky` sibling packages (an OAuth2 provider and, for
Bluesky, atproto OAuth with PAR/DPoP/PKCE).

#### Building a sign-in provider

The **documented, stable API surface** a provider package may rely on (nothing
else — reaching into undocumented internals is a plugin bug, not a supported
extension point):

- **The provider contract** (`datasette_accounts.providers`): `AuthProvider`
  (`key` / `label` / `start_path`, optional `icon` / `brand_color`, optional
  `configured(self, datasette)`), `provider_gate(key)` (the enabled-404 +
  CSRF-on-POST + method-gate decorator for your routes), `finish_login(...)`
  (the single termination point every flow returns from — see
  `LocalIdentity`/`ExternalIdentity` below), and `make_state`/`read_state`
  (core-owned, signed OAuth `state`). The demo package's README walks through
  all of these with runnable snippets.

  `configured()` is usually a plain sync method (a fixed set of env vars,
  checked instantly — see the Discord provider). It may instead be `async def`
  and return an awaited bool, for a provider whose readiness genuinely depends
  on a runtime, DB-backed value that can't be read synchronously. Core awaits
  the result only when it is itself awaitable, so an existing sync override
  needs no change.

- **Identity kinds**: hand `finish_login` either a `LocalIdentity(user_id)` —
  you've already resolved an existing account (a password-flow completion) — or
  an `ExternalIdentity(provider, subject, email=, email_verified=,
  username_hint=, display_name=)` — you've proven control of a third-party
  identity and let core map `(provider, subject)` to an account through the
  identities table, applying the per-provider signups policy for a first-seen
  identity. `subject` must be the IdP's stable id, **never** an email.

- **Also public for provider tests** (`datasette_accounts.providers`):
  `get_registry(datasette)` (the `{key: AuthProvider}` registry) and
  `provider_source(provider)` (a provider's distribution package), plus the
  `STATE_COOKIE` constant and, from `datasette_accounts.security`, the module
  itself and its `COOKIE_NAME` / `SIGN_NAMESPACE` constants — enough to assert a
  session was minted and to inspect the state cookie in an end-to-end test. See
  `tests/test_demo_provider.py`, which drives the installed demo package through
  the full external path using only these.

- **Token hygiene — patterns to copy, not a shared helper.** A magic-link-style
  provider needs its own one-time token table (core's own invite/reset tokens
  are **not** public API — don't import from `datasette_accounts.db`'s token
  helpers, and don't share core's tables). Copy the pattern core itself uses:
  - store a **sha256 hash** of the token, never the raw value;
  - **single-use, claim-by-delete**: redeeming a token is a `DELETE` (with
    `RETURNING`, or equivalent) inside your write transaction, so a double-
    submit race or an expired-but-unpurged link both simply find nothing to
    claim;
  - a **TTL**, checked in the same delete (an expired row is indistinguishable
    from a missing one to the caller);
  - **one live token per target** — minting a new one invalidates whatever
    the target already had, so an old, forgotten link can never be redeemed
    alongside a fresh one.

  A shared token helper may be extracted from core later once a second real
  consumer exists; for now, treat this as a pattern to reimplement, not a
  dependency to reach for.

Read the demo package's README for the full security checklist (wrap every route
in `provider_gate`, never match by email, never set cookies yourself, always
`read_state` on a callback, verify the IdP's response before trusting it).

## Configuration

All options live under the `datasette-accounts` plugin block and have safe
defaults (a zero-config install works — it just warns about persistence):

| option | type | default | meaning |
|--------|------|---------|---------|
| `session_ttl_days` | int | `14` | absolute session lifetime |
| `password_min_length` | int | `8` | minimum new-password length (max is fixed at 1024) |
| `lockout_threshold` | int | `5` | consecutive failures before lock; `0` disables lockout |
| `lockout_minutes` | int | `15` | auto-unlock window after a lock |
| `secure_cookie` | `"auto"` / `true` / `false` | `"auto"` | Secure flag on the session cookie; set `true` when serving over HTTPS |
| `audit_retention_days` | int | `90` | delete `login_audit` rows older than this; `0` = keep forever |
| `admin_audit_retention_days` | int | `0` (keep forever) | delete admin-audit rows older than this |
| `invite_ttl_hours` | int | `72` | invite-link lifetime |
| `reset_link_ttl_hours` | int | `24` | reset-link lifetime |
| `max_pending_registrations` | int | `20` | refuse new self-registrations while the pending-approval queue is at this size |
| `registrations_per_ip_per_day` | int | `5` | per-IP daily self-registration cap (uses the client IP, so `trust_proxy_headers` applies) |

```yaml
plugins:
  datasette-accounts:
    session_ttl_days: 30
    password_min_length: 12
    secure_cookie: true
    audit_retention_days: 30
```

### User profiles

Accounts are seeded into [`datasette-user-profiles`](https://github.com/simonw/datasette-user-profiles)
automatically, but its profile pages are gated by the `profile_access`
permission, which denies by default. Grant it to every signed-in account so they
can view and edit their own profile:

```yaml
permissions:
  profile_access:
    id: "*"        # any actor with an id — i.e. any signed-in account
```

or on the command line:

```bash
datasette mydata.db --internal accounts.db -s permissions.profile_access.id '*'
```

## Development

See [`docs/DEVELOPMENT.md`](docs/DEVELOPMENT.md) for the security model, setup,
and the dev loop.

## License

Apache-2.0
