# 01 — Architecture, stack & dev

## Version targets

- **Datasette ≥ 1.0a23.** Forced by two constraints: the fullstack skill pins
  `datasette>=1.0a23`, and `datasette-user-profiles` uses the 1.0 permission API
  (`register_actions` + `await datasette.allowed(...)`). We therefore target the 1.0
  action API, **not** the classic `register_permissions`/`permission_allowed` path
  used by `datasette-auth-passwords`.
- Python ≥ 3.10.

## Dependencies

Runtime (per the fullstack skill):
- `datasette>=1.0a23`
- `datasette-plugin-router>=0.0.1a2` — routing + `@check_permission`-style decorators + OpenAPI generation
- `datasette-vite>=0.0.1a3` — serves the built Svelte assets (`vite_entry`, `vite_js_urls`)
- `pydantic>=2` — page-data + API request/response contracts
- `python-ulid>=3` — account ids
- `sqlite-migrate>=0.1b0`, `sqlite-utils>=3.38` — internal-DB migrations

No new hashing dependency: PBKDF2 is stdlib (see [`03-authentication.md`](03-authentication.md)).

Dev: `pytest`, `pytest-asyncio`, `ruff`. Frontend: `svelte ^5`, `vite ^7`,
`@sveltejs/vite-plugin-svelte`, `openapi-fetch`, `openapi-typescript`,
`json-schema-to-typescript`, `typescript`.

## Package layout (fullstack-skill convention)

```
datasette-accounts/
  datasette_accounts/          # Python package (underscores)
    __init__.py                        # hooks: register_routes, register_actions,
                                       #   startup, actor_from_request, menu_links,
                                       #   extra_template_vars, register_commands
    router.py                          # shared Router() + admin permission decorator
    page_data.py                       # Pydantic models (page data + API req/resp)
    internal_db.py                     # DB read/write helpers
    internal_migrations.py             # sqlite-migrate schema (namespace below)
    passwords.py                       # PBKDF2 hash/verify (copied from auth-passwords)
    sessions.py                        # token mint / hash / lookup / revoke
    routes/
      __init__.py
      pages.py                         # GET/HTML shells (login, admin, account)
      api.py                           # JSON endpoints (authenticate, admin ops, self)
    templates/
      accounts_base.html            # single base template
    static/                            # BUILT frontend assets (Vite output) — shipped
    manifest.json                      # Vite manifest — shipped
  frontend/                            # Svelte/Vite/TS source — NOT shipped in wheel
    src/pages/{login,admin,account}/…
    src/page_data/…                    # generated *.types.ts from Pydantic schemas
    api.d.ts                           # generated OpenAPI types
    vite.config.ts, package.json, …
  scripts/typegen-pagedata.py
  tests/test_accounts.py
  pyproject.toml
  Justfile
  CLAUDE.md  (+ AGENTS.md symlink)
  plans/  plan.html
```

Vite builds into `datasette_accounts/static/gen/` and writes
`manifest.json` into the package. `pyproject.toml` ships
`static/**`, `templates/*`, `manifest.json` via `[tool.setuptools.package-data]`
and excludes `frontend`.

Entry point:
```toml
[project.entry-points.datasette]
accounts = "datasette_accounts"
```

## Migration namespace

`Migrations("datasette-accounts.internal")` — distinct from
`datasette-user-profiles.internal` so migration bookkeeping never interleaves.

## Dev ports

Fullstack-skill port registry already uses 8004/5177, 8005/5178, 7006/5179.
We take **Datasette 8006 / Vite 5180** (update `DEV_PORT` in `vite.config.ts`,
the `frontend-dev --port`, and `DATASETTE_AUTH_BASIC_LOGIN_VITE_PATH`).

Three-terminal dev loop: `just frontend-dev`, `just dev-with-hmr`, `just types-watch`.
Pre-commit: `just format`, `just check`, `uv run pytest`.

## Frontend serving

Each page is its own Vite entry (`login`, `admin`, `account`). The base template
calls `datasette_accounts_vite_entry(entrypoint)` (from `datasette-vite`)
in `extra_head`, mounts Svelte to `#app-root`, and passes initial data via
`<script id="pageData">{{ page_data | tojson }}</script>`. Page data uses
`model_dump()` (dict), never `model_dump_json()`.
