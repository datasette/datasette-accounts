# The core PR train

Stacked branches, PRs opened together, merged top-down when reviewed
(A2-D4). Every PR: built by an Opus agent from its ticket, then
Fable-reviewed (security-critical code read line-by-line), tests re-run
independently, committed by the main loop. Base: `main` @ `a3965e5`
(pushed to origin 2026-07-21).

| # | Branch | PR | Commit | Tests | Contents (1-line) |
|---|--------|----|--------|-------|-------------------|
| 1 | auth2/01-contract | [#12](https://github.com/datasette/datasette-accounts/pull/12) | `12020ce` | 312 | Hookspec, AuthProvider (branding + sync/async configured()), registry, signed state, provider_gate, finish_login (Local only) |
| 2 | auth2/02-password-provider | [#13](https://github.com/datasette/datasette-accounts/pull/13) | `72f24b4` | 312 | Password flow → providers/password.py, all mints via finish_login, cookie helpers consolidated; pixel-identical login |
| 3 | auth2/03-identities-external | [#14](https://github.com/datasette/datasette-accounts/pull/14) | `3011abf` | 344 | m009 identities + provenance + D5 signups rewrite; external path w/ enabled re-check; signups off/approval/auto; provisioning |
| 4 | auth2/04-linking | [#15](https://github.com/datasette/datasette-accounts/pull/15) | `20065db` | 366 | Link/step-up intents, live-actor⇔bound-actor check, 409-never-mint, strand-guarded unlink, admin unlink, link-start/unlink APIs |
| 5 | auth2/05-admin-cli | *(no PR yet)* | `9e0c63d` | 380 | set_provider_enabled/signups (audited, in-tx last-provider guard), /-/admin/api/set-provider, providers CLI, break-glass, carried-debt 404 gates |
| 6 | auth2/06-frontend | — | *building* | — | Login provider buttons, account Sign-in methods, Config providers card, page-data + countIdentitiesByProvider |
| 7 | auth2/07-demo | — | backlog | — | Demo provider package, provider-author docs, registry-exact-test fixes |

## Per-PR review notes (what a reviewer/agent should know)

- **#12**: `_error_page` interpolates only the constant generic message —
  keep it that way. Enabled re-check is deliberately absent from the local
  path (matches reference; external-only by design).
- **#13**: `set_password_complete` mints via `mint_session`, NOT
  finish_login — reference-faithful (response-shape reasons, same comment).
  `password.py` reaches the KDF via a function-local `from ..routes import
  api` (no import cycle; keeps `api.averify_dummy` monkeypatchable).
- **#14**: link/step-up intent dispatch sits BEFORE the matched-identity
  mint — a deliberate hardening over the M3 reference (M3 checked only the
  unmatched branch; final reference moved it up in M4). Do not move it down.
- **#15**: proof-TTL enforcement rides on proof *presence* — sound because
  only the password-verify path mints proof-less link states and states are
  core-signed. Vanished step-up target ⇒ dead 302 via the
  `provider_start_path` fallback, never a 500.
- **05**: last-provider guard takes `installed_keys` injected from the
  registry (db.py must not import __init__). Break-glass = enabling is
  never guarded + CLI writes the internal DB directly. Carried-debt gates:
  authenticate 404s pre-KDF; register 404s when password disabled;
  set-password deliberately ungated (invite/reset = admin act).

## PR mechanics

- #12's base is `main`; #13→#12's branch; #14→#13's; #15→#14's; continue
  the pattern for #16–18.
- 2026-07-21: #12 initially showed 4 stray commits because origin/main was
  stale; fixed by pushing main then close/reopen #12 to force a merge-base
  recompute. If a PR's diff ever looks wrong after a base push, that's the
  trick.
- Rebase discipline: from the train tip run `git rebase --update-refs`,
  then force-push ALL train branches together. Not yet exercised — first
  real use comes with the GHA-failure fix pass.
