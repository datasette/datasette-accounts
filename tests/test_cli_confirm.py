"""The confirmation gate: mutations prompt "are you sure?" unless --yes."""

from cli_util import make_admin, query, run


def test_confirm_declined_aborts(tmp_path):
    db = str(tmp_path / "a.db")
    result = run("create", "zed", "-i", db, input="n\n")
    assert result.exit_code == 1
    assert "Aborted" in result.output
    assert query(db, "SELECT count(*) c FROM datasette_accounts_users")[0]["c"] == 0


def test_confirm_accepted_at_prompt(tmp_path):
    db = str(tmp_path / "a.db")
    result = run("create", "zed", "-i", db, input="y\n")
    assert result.exit_code == 0
    assert query(db, "SELECT count(*) c FROM datasette_accounts_users")[0]["c"] == 1


def test_delete_declined_leaves_user(tmp_path):
    db = str(tmp_path / "a.db")
    make_admin(db, "admin")
    run("create", "alice", "-y", "-i", db)
    result = run("delete", "alice", "-i", db, input="n\n")
    assert result.exit_code == 1
    assert (
        query(
            db, "SELECT count(*) c FROM datasette_accounts_users WHERE username='alice'"
        )[0]["c"]
        == 1
    )
