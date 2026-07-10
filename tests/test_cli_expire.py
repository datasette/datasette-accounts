"""`datasette accounts expire` + `list --expired` — account expiry deadlines."""

import datetime
import getpass
import json
import re
import sqlite3

from cli_util import make_admin, query, run

# Millisecond ISO-8601 with a +00:00 offset, e.g. 2026-07-07T22:09:25.087+00:00.
TS_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}\+00:00$")

PAST = "2020-01-01T00:00:00.000+00:00"


def set_expires_at(db_path, username, value):
    """Write expires_at directly (the command refuses past values by design)."""
    conn = sqlite3.connect(db_path)
    conn.execute(
        "UPDATE datasette_accounts_users SET expires_at = ? WHERE username = ?",
        (value, username),
    )
    conn.commit()
    conn.close()


def expires_of(db_path, username):
    return query(
        db_path,
        "SELECT expires_at FROM datasette_accounts_users WHERE username = ?",
        (username,),
    )[0]["expires_at"]


# --- expire -------------------------------------------------------------------


def test_expire_at_offset_normalizes_to_utc(tmp_path):
    db = str(tmp_path / "a.db")
    run("create", "temp", "-y", "-i", db)
    result = run("expire", "temp", "--at", "2099-01-02T03:04:05+02:00", "-y", "-i", db)
    assert result.exit_code == 0
    # The +02:00 offset is shifted to UTC and stored in the canonical
    # millisecond-+00:00 form — same normalization as the API.
    assert expires_of(db, "temp") == "2099-01-02T01:04:05.000+00:00"
    assert "2099-01-02T01:04:05.000+00:00" in result.output


def test_expire_in_days_json_shape_and_audit(tmp_path):
    db = str(tmp_path / "a.db")
    run("create", "temp", "-y", "-i", db)
    result = run("expire", "temp", "--in-days", "30", "--json", "-y", "-i", db)
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert data["ok"] is True
    assert TS_RE.match(data["expires_at"])
    stored = datetime.datetime.fromisoformat(data["expires_at"])
    ahead = stored - datetime.datetime.now(datetime.timezone.utc)
    assert 29.99 < ahead.total_seconds() / 86400 < 30.01
    assert expires_of(db, "temp") == data["expires_at"]

    audit = query(
        db, "SELECT operation, actor_id, detail FROM datasette_accounts_admin_audit"
    )[-1]
    assert audit["operation"] == "set-expiry"
    assert audit["actor_id"] == f"cli:{getpass.getuser()}"
    assert data["expires_at"] in audit["detail"]


def test_expire_clear(tmp_path):
    db = str(tmp_path / "a.db")
    run("create", "temp", "-y", "-i", db)
    run("expire", "temp", "--in-days", "30", "-y", "-i", db)
    result = run("expire", "temp", "--clear", "--json", "-y", "-i", db)
    assert result.exit_code == 0
    assert json.loads(result.output) == {"ok": True, "expires_at": None}
    assert expires_of(db, "temp") is None
    ops = [
        r["operation"]
        for r in query(db, "SELECT operation FROM datasette_accounts_admin_audit")
    ]
    assert ops[-2:] == ["set-expiry", "clear-expiry"]


def test_expire_flag_misuse_is_usage_error(tmp_path):
    db = str(tmp_path / "a.db")
    run("create", "temp", "-y", "-i", db)
    # None of the three forms.
    result = run("expire", "temp", "-y", "-i", db)
    assert result.exit_code == 2
    assert "exactly one of --at / --in-days / --clear" in result.output
    # Two at once.
    result = run(
        "expire", "temp", "--at", "2099-01-01", "--in-days", "30", "-y", "-i", db
    )
    assert result.exit_code == 2
    assert "exactly one of --at / --in-days / --clear" in result.output
    # --clear plus a value form.
    result = run("expire", "temp", "--clear", "--in-days", "30", "-y", "-i", db)
    assert result.exit_code == 2


def test_expire_bad_and_past_at_exit_1(tmp_path):
    db = str(tmp_path / "a.db")
    run("create", "temp", "-y", "-i", db)
    for bad in (["--at", "not a date"], ["--at", "2020-01-01"], ["--in-days", "0"]):
        result = run("expire", "temp", *bad, "-y", "-i", db)
        assert result.exit_code == 1, bad
        assert "Expiry must be a valid timestamp in the future" in result.output
    # Nothing was written.
    assert expires_of(db, "temp") is None


def test_expire_last_admin_exit_1(tmp_path):
    db = str(tmp_path / "a.db")
    make_admin(db, "solo")
    result = run("expire", "solo", "--in-days", "30", "-y", "-i", db)
    assert result.exit_code == 1
    assert "Cannot set an expiry on the last admin" in result.output
    assert expires_of(db, "solo") is None
    # Clearing never guards, even on the last admin.
    result = run("expire", "solo", "--clear", "-y", "-i", db)
    assert result.exit_code == 0


def test_expire_unknown_user_exit_1(tmp_path):
    db = str(tmp_path / "a.db")
    make_admin(db)  # migrate the DB so the failure is the lookup, not the schema
    result = run("expire", "ghost", "--in-days", "30", "-y", "-i", db)
    assert result.exit_code == 1
    assert "no such user" in result.output


# --- list --expired -------------------------------------------------------------


def test_list_expired_filter_and_column(tmp_path):
    db = str(tmp_path / "a.db")
    run("create", "alice", "-y", "-i", db)
    run("create", "temp", "-y", "-i", db)
    set_expires_at(db, "temp", PAST)

    result = run("list", "--expired", "-i", db)
    assert result.exit_code == 0
    assert "temp" in result.output
    assert "alice" not in result.output
    # The expiry column renders (header + the stored deadline).
    assert "expires" in result.output
    assert PAST in result.output

    # --json rows carry the expiry fields from to_user_row.
    result = run("list", "--json", "-i", db)
    users = {u["username"]: u for u in json.loads(result.output)["users"]}
    assert users["temp"]["expired"] is True
    assert users["temp"]["expires_at"] == PAST
    assert users["alice"]["expired"] is False
    assert users["alice"]["expires_at"] is None
