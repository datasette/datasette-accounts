"""`datasette accounts bootstrap-admin` — idempotency, --force, enabled-only count."""

import sqlite3

from cli_util import make_admin, query, run


def test_bootstrap_admin_idempotent(tmp_path):
    db = str(tmp_path / "a.db")
    first = make_admin(db, "root1")
    assert first.exit_code == 0
    # An enabled admin now exists → skip, exit 0 (no confirmation needed).
    second = make_admin(db, "root2")
    assert second.exit_code == 0
    assert "skipping" in second.output
    assert query(db, "SELECT count(*) c FROM datasette_accounts_users")[0]["c"] == 1


def test_bootstrap_admin_force(tmp_path):
    db = str(tmp_path / "a.db")
    make_admin(db, "root1")
    result = run(
        "bootstrap-admin",
        "root2",
        "--password",
        "adminpass123",
        "--force",
        "-y",
        "-i",
        db,
    )
    assert result.exit_code == 0
    assert query(db, "SELECT count(*) c FROM datasette_accounts_users")[0]["c"] == 2


def test_bootstrap_admin_disabled_admin_does_not_count(tmp_path):
    db = str(tmp_path / "a.db")
    # Seed a *disabled* admin directly (the last-admin guard makes this state
    # unreachable through the CLI, but it's exactly what the count must ignore).
    run("create", "seed", "-y", "-i", db)  # init the schema
    conn = sqlite3.connect(db)
    conn.execute(
        "INSERT INTO datasette_accounts_users "
        "(id, username, password_hash, is_admin, disabled, "
        " must_change_password, failed_attempts, created_at, updated_at) "
        "VALUES ('x', 'olddisabled', 'h', 1, 1, 0, 0, "
        "'2026-01-01T00:00:00.000+00:00', '2026-01-01T00:00:00.000+00:00')"
    )
    conn.commit()
    conn.close()
    # No *enabled* admin exists, so bootstrap creates one instead of skipping.
    result = make_admin(db, "root2")
    assert result.exit_code == 0
    assert "skipping" not in result.output
    assert (
        query(
            db, "SELECT count(*) c FROM datasette_accounts_users WHERE username='root2'"
        )[0]["c"]
        == 1
    )


def test_bootstrap_admin_must_change_defaults_off(tmp_path):
    db = str(tmp_path / "a.db")
    make_admin(db, "root1")
    row = query(db, "SELECT must_change_password FROM datasette_accounts_users")[0]
    assert row["must_change_password"] == 0
