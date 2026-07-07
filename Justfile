# datasette-accounts — dev recipes
# Ports: Datasette 8006 / Vite 5180

# Regenerate all TypeScript types (OpenAPI + page-data)
types: types-pagedata

# Page-data JSON schemas -> TS (also compiled by the Vite buildStart plugin)
types-pagedata:
    uv run python scripts/typegen-pagedata.py

# Build the frontend for production (outputs into the package)
frontend *flags:
    npm run build --prefix frontend {{flags}}

# Vite dev server (HMR)
frontend-dev *flags:
    npm run dev --prefix frontend -- --port 5180 {{flags}}

# Datasette dev server with a persistent internal DB
dev *flags:
    uv run datasette --root -p 8006 --internal accounts.db {{flags}}

# Datasette + Vite HMR (auto-restart on .py/.html changes)
dev-with-hmr *flags:
    DATASETTE_AUTH_BASIC_LOGIN_VITE_PATH=http://localhost:5180/ \
    watchexec --stop-signal SIGKILL -e py,html --ignore '*.db' --restart --clear -- \
      just dev {{flags}}

# Tests
test:
    uv run pytest -q

# Lint / format
check:
    uv run ruff check datasette_accounts tests
    npm run check --prefix frontend

format:
    uv run ruff format datasette_accounts tests
    npm run format --prefix frontend

# Hash a password with the plugin's PBKDF2 scheme
hash-password *ARGS:
    uv run datasette hash-password {{ARGS}}
