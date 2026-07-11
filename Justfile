# datasette-accounts — dev recipes
# Ports: Datasette 8006 / Vite 5180

# Regenerate all TypeScript types (OpenAPI + page-data)
types: types-pagedata

# Page-data Pydantic models -> JSON schemas -> TS. The Python step writes
# *_schema.json; the node step compiles those to *.types.ts (the same
# compile the Vite buildStart plugin runs, so a full build isn't required).
types-pagedata:
    uv run python scripts/typegen-pagedata.py
    npm run gen-types --prefix frontend

# Build the frontend for production (outputs into the package)
frontend *flags:
    npm run build --prefix frontend {{flags}}

# Vite dev server (HMR)
frontend-dev *flags:
    npm run dev --prefix frontend -- --port 5180 {{flags}}

# Datasette dev server with a persistent internal DB.
# Grants datasette-user-profiles' `profile_access` to every signed-in account
# ({"id": "*"} matches any actor with an id), so accounts can view/edit profiles.
dev *flags:
    DATASETTE_SECRET=abc123 uv run datasette --root -p 8006 --internal accounts.db \
      -s permissions.profile_access.id '*' \
      --plugins-dir samples/discord-auth {{flags}}

# Datasette + Vite HMR (auto-restart on .py/.html changes)
dev-with-hmr *flags:
    DATASETTE_AUTH_BASIC_LOGIN_VITE_PATH=http://localhost:5180/ \
    watchexec --stop-signal SIGKILL -e py,html --ignore '*.db' --restart --clear -- \
      just dev {{flags}}

# Regenerate committed doc screenshots → docs/screenshots/*.png.
# Run all, or a subset by name: `just shots` / `just shots login admin`.
shots *names:
    npm --prefix frontend exec -- playwright install chromium
    node frontend/scripts/screenshots.mjs {{names}}

# --- Codegen: SQL queries ---

# Regenerate datasette_accounts/sql/_queries_generated.py from queries.sql.
#
# internal_migrations.py is the single source of truth for schema. We apply it
# to an ephemeral sqlite file, then point `solite codegen` at that .db so it can
# resolve column types + nullability from the post-migration state. The JSON IR
# (_queries.sql.json) is an intermediate — gitignored, not checked in.
# tools/gen_queries.py turns the IR into `conn`-first Python helpers that slot
# into db.py's execute_fn / execute_write_fn closures.
codegen-queries:
    #!/usr/bin/env bash
    set -euo pipefail
    # solite --schema keys off file extension; mktemp -u returns an
    # extensionless path so we append .db.
    tmp_db=$(mktemp -u).db
    trap "rm -f $tmp_db" EXIT
    uv run python tools/gen_schema_db.py "$tmp_db"
    uv run solite codegen \
        --schema "$tmp_db" \
        datasette_accounts/sql/queries.sql \
        > datasette_accounts/sql/_queries.sql.json
    uv run python tools/gen_queries.py \
        datasette_accounts/sql/_queries.sql.json \
        > datasette_accounts/sql/_queries_generated.py
    uv run ruff format datasette_accounts/sql/_queries_generated.py

# CI gate: regenerate into a temp file and diff against the checked-in helper.
# Fails if `just codegen-queries` wasn't run after editing queries.sql /
# internal_migrations.py / tools/gen_queries.py.
check-queries-fresh:
    #!/usr/bin/env bash
    set -euo pipefail
    tmp_db=$(mktemp -u).db
    tmp_ir=$(mktemp)
    tmp_py=$(mktemp)
    trap "rm -f $tmp_db $tmp_ir $tmp_py" EXIT
    uv run python tools/gen_schema_db.py "$tmp_db"
    uv run solite codegen \
        --schema "$tmp_db" \
        datasette_accounts/sql/queries.sql \
        > "$tmp_ir"
    uv run python tools/gen_queries.py "$tmp_ir" > "$tmp_py"
    uv run ruff format --quiet "$tmp_py"
    diff -u datasette_accounts/sql/_queries_generated.py "$tmp_py" || {
        echo "::error:: _queries_generated.py is stale — run \`just codegen-queries\`"
        exit 1
    }

schema:
    rm -f schema.db
    uv run sqlite-utils migrate schema.db datasette_accounts/internal_migrations.py >/dev/null

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
