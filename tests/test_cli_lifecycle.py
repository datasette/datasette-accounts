"""Lifecycle subcommands: last-admin guard, promote/demote, reset-password."""

import sqlite3

from cli_util import make_admin, query, run


def test_last_admin_guard_on_demote_disable_delete(tmp_path):
    db = str(tmp_path / "a.db")
    make_admin(db, "solo")
    for cmd in ("demote", "disable"):
        result = run(cmd, "solo", "-y", "-i", db)
        assert result.exit_code == 1, cmd
        assert "last admin" in result.output
    result = run("delete", "solo", "-y", "-i", db)
    assert result.exit_code == 1
    assert "last admin" in result.output
    # Still present + still an enabled admin.
    row = query(db, "SELECT is_admin, disabled FROM datasette_accounts_users")[0]
    assert row == {"is_admin": 1, "disabled": 0}


def test_promote_demote_noop(tmp_path):
    db = str(tmp_path / "a.db")
    run("create", "alice", "-y", "-i", db)
    # A no-op needs no confirmation (it returns before the mutation).
    assert "no change" in run("demote", "alice", "-i", db).output
    run("promote", "alice", "-y", "-i", db)
    assert "no change" in run("promote", "alice", "-i", db).output


def test_reset_password_forces_change_and_revokes_sessions(tmp_path):
    db = str(tmp_path / "a.db")
    run(
        "create",
        "alice",
        "--password",
        "origpass123",
        "--no-must-change",
        "-y",
        "-i",
        db,
    )
    uid = query(db, "SELECT id FROM datasette_accounts_users")[0]["id"]
    # Seed a live session for alice directly.
    conn = sqlite3.connect(db)
    conn.execute(
        "INSERT INTO datasette_accounts_sessions "
        "(token_sha256, actor_id, created_at, expires_at, last_seen_at) "
        "VALUES ('tok', ?, '2026-01-01T00:00:00.000+00:00', "
        "'2099-01-01T00:00:00.000+00:00', '2026-01-01T00:00:00.000+00:00')",
        (uid,),
    )
    conn.commit()
    conn.close()

    result = run("reset-password", "alice", "--generate", "-y", "-i", db)
    assert result.exit_code == 0
    row = query(db, "SELECT must_change_password FROM datasette_accounts_users")[0]
    assert row["must_change_password"] == 1
    sessions = query(db, "SELECT count(*) c FROM datasette_accounts_sessions")[0]["c"]
    assert sessions == 0
