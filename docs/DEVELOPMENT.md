# Development

## Security model

- **Identity + global capabilities.** This plugin owns accounts, passwords,
  sessions, one `is_admin` flag, and admin-managed grants of **global** actions.
  It emits an actor of the shape `{"id": "<ULID>", "username": "…", "is_admin":
  bool}` that config `allow` blocks (and other plugins) can consume for
  resource-level authorization. Capability grants are allow-only and never emit a
  deny.
- **Passwords** use PBKDF2-HMAC-SHA256 (480,000 iterations), run in a thread so a
  verification never blocks the event loop.
- **CSRF** is enforced unconditionally in the plugin (JSON Content-Type +
  `Origin`/`Sec-Fetch-Site`), not by relying on middleware. All mutation
  endpoints are POST-only.
- **Forced password change** is enforced globally via an `asgi_wrapper`: a user
  with a temporary password can reach only the account/change-password/logout
  pages until they change it.
- **Audit**: `login_audit` records login and change-password attempts;
  `admin_audit` records every admin mutation (who, what, when, target).

## Setup

```bash
uv sync                       # Python deps
npm install --prefix frontend # frontend deps
just types                    # regenerate page-data types
just frontend                 # build the Svelte frontend
just test                     # pytest
just check                    # ruff + svelte-check
just shots                    # regenerate docs/screenshots/*.png (Playwright)
```

## Screenshots

`just shots` boots a throwaway Datasette with seeded demo accounts
(`frontend/scripts/shot-plugins/seed.py`), drives Playwright through the pages
(`frontend/scripts/screenshots.mjs`), and writes the committed PNGs. It is
deterministic — a re-run with no UI change produces no git diff — and is a
manual local task, never run in CI.

## Dev loop

Three-terminal dev loop (Datasette 8006 / Vite 5180):

```bash
just frontend-dev     # Vite HMR
just dev-with-hmr     # Datasette, restarts on .py changes
```
