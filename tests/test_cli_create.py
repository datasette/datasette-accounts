"""`datasette accounts create` — explicit, generated, stdin, and interactive."""

import json

from cli_util import query, run

from datasette_accounts.passwords import verify_password


def test_create_generated_echoes_password_once(tmp_path):
    db = str(tmp_path / "a.db")
    result = run("create", "alice", "-y", "-i", db, "--actor", "cli:tester")
    assert result.exit_code == 0
    lines = [ln for ln in result.output.splitlines() if "shown once" in ln]
    assert len(lines) == 1
    password = lines[0].split(": ", 1)[1]
    assert len(password) >= 20
    rows = query(db, "SELECT username, is_admin FROM datasette_accounts_users")
    assert rows == [{"username": "alice", "is_admin": 0}]


def test_create_explicit_admin(tmp_path):
    db = str(tmp_path / "a.db")
    result = run(
        "create", "bob", "--admin", "--password", "supersecret1", "-y", "-i", db
    )
    assert result.exit_code == 0
    # An explicit password is never echoed.
    assert "shown once" not in result.output
    rows = query(
        db, "SELECT is_admin, must_change_password FROM datasette_accounts_users"
    )
    assert rows == [{"is_admin": 1, "must_change_password": 1}]


def test_create_duplicate_is_exit_1(tmp_path):
    db = str(tmp_path / "a.db")
    run("create", "alice", "-y", "-i", db)
    result = run("create", "alice", "-y", "-i", db)
    assert result.exit_code == 1
    assert "already taken" in result.output


def test_create_password_too_short_is_exit_1(tmp_path):
    db = str(tmp_path / "a.db")
    result = run("create", "carol", "--password", "ab", "-y", "-i", db)
    assert result.exit_code == 1
    assert "at least 8 characters" in result.output
    assert query(db, "SELECT count(*) c FROM datasette_accounts_users")[0]["c"] == 0


def test_create_password_stdin(tmp_path):
    db = str(tmp_path / "a.db")
    result = run(
        "create", "dave", "--password-stdin", "-y", "-i", db, input="frompipe123\n"
    )
    assert result.exit_code == 0
    row = query(db, "SELECT password_hash FROM datasette_accounts_users")[0]
    # The stdin secret is the account password (verifiable against the hash).
    assert verify_password("frompipe123", row["password_hash"])


def test_create_min_length_from_metadata(tmp_path):
    db = str(tmp_path / "a.db")
    cfg = tmp_path / "cfg.json"
    cfg.write_text(
        json.dumps({"plugins": {"datasette-accounts": {"password_min_length": 15}}})
    )
    result = run(
        "create", "x", "--password", "short12chars", "-y", "-m", str(cfg), "-i", db
    )
    assert result.exit_code == 1
    assert "at least 15" in result.output


# --- interactive mode (-I prompts for anything not supplied) ----------------


def test_interactive_create_generated(tmp_path):
    db = str(tmp_path / "a.db")
    # Prompts: username, admin?, force-change?, generate?, confirm.
    result = run("create", "-I", "-i", db, input="alice\ny\ny\ny\ny\n")
    assert result.exit_code == 0, result.output
    assert "shown once" in result.output
    row = query(
        db,
        "SELECT username, is_admin, must_change_password FROM datasette_accounts_users",
    )[0]
    assert row == {"username": "alice", "is_admin": 1, "must_change_password": 1}


def test_interactive_create_typed_password(tmp_path):
    db = str(tmp_path / "a.db")
    # username, admin? n, force-change? n, generate? n, password x2, confirm.
    result = run(
        "create",
        "-I",
        "-i",
        db,
        input="bob\nn\nn\nn\nMypassw0rd1\nMypassw0rd1\ny\n",
    )
    assert result.exit_code == 0, result.output
    assert "shown once" not in result.output
    row = query(
        db,
        "SELECT is_admin, must_change_password, password_hash "
        "FROM datasette_accounts_users",
    )[0]
    assert row["is_admin"] == 0 and row["must_change_password"] == 0
    assert verify_password("Mypassw0rd1", row["password_hash"])


def test_interactive_missing_username_non_interactive_errors(tmp_path):
    db = str(tmp_path / "a.db")
    # No username and not interactive → a usage-style error, nothing created.
    result = run("create", "-y", "-i", db)
    assert result.exit_code == 1
    assert "USERNAME" in result.output
