"""`datasette accounts registration` / `approve` / `reject` + `list
--awaiting-approval` — the CLI counterparts of the self-registration flow
(see plans/self-registration)."""

import asyncio
import getpass
import json
import sqlite3

from cli_util import make_admin, query, run

from datasette_accounts.passwords import hash_password

JSON_HEADERS = {"content-type": "application/json"}
TS = "2026-01-01T00:00:00.000+00:00"


def make_pending(db_path, username="applicant", password="password123"):
    """Insert a pending self-registered account directly (schema must already
    be migrated — run any command first)."""
    conn = sqlite3.connect(db_path)
    conn.execute(
        "INSERT INTO datasette_accounts_users (id, username, password_hash, "
        "is_admin, disabled, must_change_password, failed_attempts, locked_until, "
        "created_at, updated_at, pending_approval) "
        "VALUES (?, ?, ?, 0, 0, 0, 0, NULL, ?, ?, 1)",
        (f"id-{username}", username, hash_password(password), TS, TS),
    )
    conn.commit()
    conn.close()


def registration_setting(db_path):
    # Self-registration migrated to the password provider's signups policy
    # (auth-providers m009 / D5): the legacy 'registration_enabled' row became
    # 'provider:password:signups', with 'approval' standing in for the old '1'.
    rows = query(
        db_path,
        "SELECT value FROM datasette_accounts_settings "
        "WHERE key = 'provider:password:signups'",
    )
    return rows[0]["value"] if rows else None


def http(db_path, method, path, body=None):
    """Drive the real HTTP app against the CLI's internal DB — the same
    reconstruction trick base._open_internal uses, for end-to-end checks."""
    from datasette.app import Datasette

    async def go():
        ds = Datasette(internal=db_path)
        await ds.invoke_startup()
        if method == "GET":
            return await ds.client.get(path)
        return await ds.client.post(
            path, content=json.dumps(body or {}), headers=JSON_HEADERS
        )

    return asyncio.run(go())


def can_log_in(db_path, username, password):
    r = http(
        db_path,
        "POST",
        "/-/login/api/authenticate",
        {"username": username, "password": password},
    )
    return r.status_code == 200


# --- registration ---------------------------------------------------------


def test_registration_status_defaults_off(tmp_path):
    db = str(tmp_path / "a.db")
    make_admin(db)  # migrate the schema
    result = run("registration", "-i", db)  # bare invocation defaults to status
    assert result.exit_code == 0
    assert "Self-registration is off." in result.output

    result = run("registration", "status", "--json", "-i", db)
    assert result.exit_code == 0
    assert json.loads(result.output) == {"ok": True, "enabled": False}


def test_registration_on_off_flip_audit_and_liveness(tmp_path):
    db = str(tmp_path / "a.db")
    make_admin(db)

    result = run("registration", "on", "-y", "-i", db)
    assert result.exit_code == 0
    assert "Enabled self-registration." in result.output
    assert registration_setting(db) == "approval"
    assert "Self-registration is on." in run("registration", "status", "-i", db).output

    # The toggle is live: the register endpoint accepts a request end to end.
    r = http(
        db,
        "POST",
        "/-/register/api/submit",
        {"username": "newperson", "password": "password123"},
    )
    assert r.status_code == 200
    pending = query(
        db,
        "SELECT pending_approval FROM datasette_accounts_users "
        "WHERE username = 'newperson'",
    )
    assert pending == [{"pending_approval": 1}]

    result = run("registration", "off", "-y", "-i", db)
    assert result.exit_code == 0
    assert "Disabled self-registration." in result.output
    assert registration_setting(db) is None  # absence = off

    # ...and closed again: the page 404s.
    assert http(db, "GET", "/-/register").status_code == 404

    # Both flips audited with the CLI actor attribution. Self-registration is
    # now the password provider's signups policy (D5), so the toggle writes the
    # unified set-provider-signups op (the enable/disable-registration ops are
    # retired), with the mode carried in the detail.
    audit = query(
        db,
        "SELECT operation, actor_id, detail FROM datasette_accounts_admin_audit "
        "WHERE operation = 'set-provider-signups' ORDER BY id",
    )
    assert [a["operation"] for a in audit] == [
        "set-provider-signups",
        "set-provider-signups",
    ]
    assert [json.loads(a["detail"]) for a in audit] == [
        {"provider": "password", "mode": "approval"},
        {"provider": "password", "mode": "off"},
    ]
    assert all(a["actor_id"] == f"cli:{getpass.getuser()}" for a in audit)


def test_registration_noop_flip_no_confirm_no_audit(tmp_path):
    db = str(tmp_path / "a.db")
    make_admin(db)
    run("registration", "on", "-y", "-i", db)

    # A no-op needs no confirmation (no -y here) and writes no audit row.
    result = run("registration", "on", "-i", db)
    assert result.exit_code == 0
    assert "already on — no change." in result.output
    result = run("registration", "on", "--json", "-i", db)
    assert json.loads(result.output) == {"ok": True, "enabled": True}

    audit = query(
        db,
        "SELECT operation FROM datasette_accounts_admin_audit "
        "WHERE operation = 'set-provider-signups'",
    )
    assert len(audit) == 1

    # Same for off when already off.
    run("registration", "off", "-y", "-i", db)
    result = run("registration", "off", "-i", db)
    assert result.exit_code == 0
    assert "already off — no change." in result.output


def test_registration_json_shapes(tmp_path):
    db = str(tmp_path / "a.db")
    make_admin(db)
    on = run("registration", "on", "--json", "-y", "-i", db)
    assert json.loads(on.output) == {"ok": True, "enabled": True}
    off = run("registration", "off", "--json", "-y", "-i", db)
    assert json.loads(off.output) == {"ok": True, "enabled": False}


# --- approve ----------------------------------------------------------------


def test_approve_pending_account_end_to_end(tmp_path):
    db = str(tmp_path / "a.db")
    make_admin(db)
    make_pending(db, "applicant")

    # Pending: the chosen password does not sign in.
    assert not can_log_in(db, "applicant", "password123")

    result = run("approve", "applicant", "-y", "-i", db)
    assert result.exit_code == 0
    assert "Approved applicant." in result.output
    row = query(
        db,
        "SELECT pending_approval FROM datasette_accounts_users "
        "WHERE username = 'applicant'",
    )[0]
    assert row["pending_approval"] == 0

    audit = query(
        db,
        "SELECT actor_id, target_id FROM datasette_accounts_admin_audit "
        "WHERE operation = 'approve'",
    )
    assert len(audit) == 1
    assert audit[0]["actor_id"] == f"cli:{getpass.getuser()}"
    assert audit[0]["target_id"] == "id-applicant"

    # Approved: the account CAN now log in with the password it chose.
    assert can_log_in(db, "applicant", "password123")


def test_approve_non_pending_is_noop(tmp_path):
    db = str(tmp_path / "a.db")
    run("create", "alice", "-y", "-i", db)
    result = run("approve", "alice", "-i", db)  # no -y: a no-op never prompts
    assert result.exit_code == 0
    assert "not awaiting approval — no change." in result.output
    assert (
        query(
            db,
            "SELECT count(*) c FROM datasette_accounts_admin_audit "
            "WHERE operation = 'approve'",
        )[0]["c"]
        == 0
    )


# --- reject -------------------------------------------------------------------


def test_reject_deletes_and_audits_username(tmp_path):
    db = str(tmp_path / "a.db")
    make_admin(db)
    make_pending(db, "applicant")

    result = run("reject", "applicant", "-y", "-i", db)
    assert result.exit_code == 0
    assert "Rejected applicant" in result.output
    assert (
        query(
            db,
            "SELECT count(*) c FROM datasette_accounts_users "
            "WHERE username = 'applicant'",
        )[0]["c"]
        == 0
    )
    # The row is gone — the audit detail keeps the username findable.
    audit = query(
        db,
        "SELECT actor_id, detail FROM datasette_accounts_admin_audit "
        "WHERE operation = 'reject'",
    )
    assert len(audit) == 1
    assert audit[0]["actor_id"] == f"cli:{getpass.getuser()}"
    assert json.loads(audit[0]["detail"])["username"] == "applicant"


def test_reject_non_pending_exit_1_deletes_nothing(tmp_path):
    db = str(tmp_path / "a.db")
    run("create", "alice", "-y", "-i", db)
    result = run("reject", "alice", "-y", "-i", db)
    assert result.exit_code == 1
    assert "Account is not awaiting approval" in result.output
    assert (
        query(
            db,
            "SELECT count(*) c FROM datasette_accounts_users WHERE username = 'alice'",
        )[0]["c"]
        == 1
    )


def test_approve_reject_unknown_user_exit_1(tmp_path):
    db = str(tmp_path / "a.db")
    make_admin(db)  # migrate so the failure is the lookup, not the schema
    for cmd in ("approve", "reject"):
        result = run(cmd, "ghost", "-y", "-i", db)
        assert result.exit_code == 1, cmd
        assert "no such user" in result.output


def test_reject_confirm_declined_leaves_request(tmp_path):
    db = str(tmp_path / "a.db")
    make_admin(db)
    make_pending(db, "applicant")
    result = run("reject", "applicant", "-i", db, input="n\n")
    assert result.exit_code == 1
    assert "Aborted" in result.output
    assert (
        query(
            db,
            "SELECT count(*) c FROM datasette_accounts_users "
            "WHERE username = 'applicant'",
        )[0]["c"]
        == 1
    )


# --- list --awaiting-approval ---------------------------------------------------


def test_list_awaiting_approval_distinct_from_pending(tmp_path):
    db = str(tmp_path / "a.db")
    run("create", "alice", "-y", "-i", db)  # admin-created, never signed in
    make_pending(db, "bob")

    # Awaiting-approval: only the self-registered request.
    result = run("list", "--awaiting-approval", "-i", db)
    assert result.exit_code == 0
    assert "bob" in result.output
    assert "alice" not in result.output

    # Approve bob: he leaves --awaiting-approval but, never having signed in,
    # still appears under --pending — the two filters mean different things.
    run("approve", "bob", "-y", "-i", db)
    result = run("list", "--awaiting-approval", "-i", db)
    assert "bob" not in result.output
    assert "(none)" in result.output

    result = run("list", "--pending", "-i", db)
    assert "bob" in result.output
    assert "alice" in result.output

    # --json rows carry the flag; the table renders the awaiting column.
    make_pending(db, "carol")
    users = {
        u["username"]: u
        for u in json.loads(run("list", "--json", "-i", db).output)["users"]
    }
    assert users["carol"]["pending_approval"] is True
    assert users["bob"]["pending_approval"] is False
    table = run("list", "-i", db).output
    assert "awaiting" in table
