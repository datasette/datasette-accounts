# datasette-auth-basic-login — start plan

This directory is the pre-build design spec for **datasette-auth-basic-login**, a
Datasette authentication plugin that stores accounts in the internal database,
adds an admin permission for provisioning/revoking/managing accounts, and ships a
Svelte/Vite/TS frontend built with the `datasette-alex-fullstack-skill` conventions.

The design was produced through a decision-by-decision grilling session. Every
choice below is deliberate; rejected alternatives and rationale are recorded in
[`09-decisions-log.md`](09-decisions-log.md).

**Status:** the Fable 5 security review (2026-07-06) has been folded into the spec —
all 11 findings in [`../../todos/security-review/`](../../todos/security-review/README.md)
are applied. Ready for implementation.

## Read in this order

| File | Contents |
|------|----------|
| [`00-overview.md`](00-overview.md) | One-page summary of what we're building and why |
| [`01-architecture.md`](01-architecture.md) | Stack, version targets, packaging, dev workflow |
| [`02-data-model.md`](02-data-model.md) | Internal-DB tables + migrations |
| [`03-authentication.md`](03-authentication.md) | Login, sessions, cookie, `actor_from_request`, logout |
| [`04-admin-and-permissions.md`](04-admin-and-permissions.md) | Admin action, gate, bootstrap, admin UI + operations |
| [`05-self-service.md`](05-self-service.md) | Change-own-password + forced first change |
| [`06-brute-force.md`](06-brute-force.md) | Hard lockout policy |
| [`07-user-profiles-compat.md`](07-user-profiles-compat.md) | Integration with datasette-user-profiles |
| [`08-config.md`](08-config.md) | Plugin config options + defaults |
| [`09-decisions-log.md`](09-decisions-log.md) | Every decision, alternatives considered, rationale |
| [`10-implementation-plan.md`](10-implementation-plan.md) | Build order, milestones, testing |

A single-page HTML render of this spec is at [`../../plan.html`](../../plan.html).

## Reference plugins studied

- `../datasette-auth-passwords` — the auth template (PBKDF2, `/-/login`, actor cookie)
- `../datasette-acl` — permission model, admin gating, last-manager guard, audit
- `../datasette-user-profiles` — the directory layer we integrate with
- `../datasette-alex-fullstack-skill` — the Svelte/Vite/TS build conventions
- `../datasette-secrets`, `../datasette-auth-tokens` — internal-DB usage patterns
