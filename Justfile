# datasette-auth-basic-login — dev recipes

# Run the test suite
test:
    uv run pytest -q

# Lint + format check
check:
    uv run ruff check datasette_auth_basic_login tests

# Format code
format:
    uv run ruff format datasette_auth_basic_login tests

# Regenerate page-data JSON schemas (frontend typegen, M7)
types-pagedata:
    uv run python scripts/typegen-pagedata.py

# Run a dev Datasette with a persistent internal DB
dev:
    uv run datasette --root --internal accounts.db --reload

# Hash a password with the plugin's PBKDF2 scheme
hash-password *ARGS:
    uv run datasette hash-password {{ARGS}}
