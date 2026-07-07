# datasette-accounts

Username/password auth for Datasette with **database-backed accounts** in the
internal DB, an admin permission, and a Svelte/Vite/TS frontend.

## Design spec
`plans/start/` is the authoritative design (read `plans/start/README.md` first).
Security review findings are in `todos/security-review/` (all applied + built).
`plans/permissions/` is the design for admin-controlled permissions (capability
grants + datasette-acl bridge), all built on the `permissions-admin` branch.
`plans/site-messages/` is the design for the root bootstrap prompt + admin-
editable site messages (homepage sign-in prompt, login help), built on the
`site-messages` branch.

## Build status
- M0–M8 built and tested (`uv run pytest`, 22 tests green; `npm run check` clean).
  All milestones complete.
- Frontend: Svelte 5 pages (`frontend/src/pages/{login,admin,account}`) built by
  Vite into `datasette_accounts/static/gen/` + `manifest.json` (shipped).
  `routes/pages.py` renders `templates/accounts_base.html`, which mounts the
  page bundle on `#app-root` and reads `#pageData`. Pages call the JSON API via
  `frontend/src/lib/api.ts` (`postJSON`), not openapi-fetch.
- Rebuild the frontend after changing Svelte/TS: `just frontend` (or `just types`
  first if page-data models changed).

## Layout
- `__init__.py` — hooks (routes, actions, permission SQL, startup, actor,
  menu, top_homepage for the bootstrap prompt + signed-out message,
  asgi_wrapper for forced password change, hash-password CLI).
- `messages.py` — admin-editable site-message slot registry + rendering
  (bodies are admin-authored **raw HTML**, rendered verbatim — admin-only
  editor); `db.py` `site_messages` table + get/set (blank clears).
- `db.py` — internal-DB access; namespaced tables; shared admin predicate;
  transactional mutations (audit-in-same-tx, last-admin guard).
- `passwords.py` — PBKDF2 (copied from datasette-auth-passwords) + async
  wrappers (KDF runs off the event loop) + DUMMY_HASH + length bounds.
- `security.py` — CSRF gates, `?next=` validation, secure-cookie + IP-trust.
- `router.py` — shared Router + POST-only/CSRF/admin decorators.
- `routes/api.py`, `routes/pages.py` — endpoints and HTML shells.
- `grantable.py` — which global actions are grantable + principal gating +
  config-grant display; `db.py` `capability_grants` table + grant/revoke/list.
  `__init__.permission_resources_sql` emits capability-grant allow rows (F1) and
  the acl-admin bridge (F2); `datasette_acl_valid_actors` exposes accounts (F3).
  Frontend: `frontend/src/pages/capabilities`. datasette-paper is a dev dep used
  as the worked example (`datasette-paper-create`) in tests + screenshots.

## Gotchas discovered during build
- datasette-plugin-router does **not** dispatch by HTTP method: identical paths
  collide (first wins for all methods), and mutation views also answer GET.
  Mutation decorators therefore enforce POST-only; the logout page (GET
  `/-/logout`) and mutation (POST `/-/logout/perform`) use distinct paths.
- `permission_resources_sql` must return a `PermissionSQL` with a non-empty
  `params` dict (include `actor_id`) or core drops the bindings.
- `datasette_vite.vite_entry(datasette, plugin_package, manifest_dir=None)` —
  no `vite_dev_path` kwarg in the pinned version.

## Commands
`just test` · `just check` · `just format` · `just dev`
