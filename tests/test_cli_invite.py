"""`datasette accounts invite` + `reset-link` — one-time set-password links."""

import asyncio
import getpass
import json
import re

from cli_util import query, run

from datasette_accounts.passwords import hash_password, verify_password
from datasette_accounts.sessions import token_sha256

LINK_RE = re.compile(r"/-/set-password\?token=([\w-]+)")


def token_from(output):
    m = LINK_RE.search(output)
    assert m, f"no set-password link in output: {output!r}"
    return m.group(1)


def complete_link(db_path, raw_token, new_password):
    """Claim the printed token through the real db layer (proves it is live).

    Opens a Datasette on the same internal DB the CLI wrote to and calls the
    same use_password_token the HTTP completion endpoint calls.
    """
    from datasette.app import Datasette

    from datasette_accounts import db

    async def go():
        ds = Datasette(internal=db_path)
        await ds.invoke_startup()
        internal = ds.get_internal_database()
        return await db.use_password_token(
            internal, token_sha256(raw_token), hash_password(new_password)
        )

    return asyncio.run(go())


# --- invite -----------------------------------------------------------------


def test_invite_creates_account_and_prints_working_link(tmp_path):
    db = str(tmp_path / "a.db")
    result = run("invite", "nia", "-y", "-i", db)
    assert result.exit_code == 0
    assert "shown once" in result.output
    raw_token = token_from(result.output)

    # The account exists with no usable password (the "!" sentinel).
    rows = query(
        db, "SELECT username, is_admin, password_hash FROM datasette_accounts_users"
    )
    assert rows == [{"username": "nia", "is_admin": 0, "password_hash": "!"}]

    # The printed token is live: completing it sets the chosen password.
    user_id = complete_link(db, raw_token, "chosen-by-nia-1")
    assert user_id is not None
    row = query(db, "SELECT password_hash FROM datasette_accounts_users")[0]
    assert verify_password("chosen-by-nia-1", row["password_hash"])
    # Single use: the token row is gone.
    assert (
        query(db, "SELECT count(*) c FROM datasette_accounts_password_tokens")[0]["c"]
        == 0
    )


def test_invite_admin_flag_and_json_shape(tmp_path):
    db = str(tmp_path / "a.db")
    result = run("invite", "boss", "--admin", "--json", "-y", "-i", db)
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert data["ok"] is True
    assert data["username"] == "boss"
    assert data["id"]
    assert data["url"].startswith("/-/set-password?token=")
    assert query(db, "SELECT is_admin FROM datasette_accounts_users") == [
        {"is_admin": 1}
    ]


def test_invite_base_url_prefixes_link(tmp_path):
    db = str(tmp_path / "a.db")
    result = run(
        "invite",
        "nia",
        "--base-url",
        "https://data.example.com/",
        "--json",
        "-y",
        "-i",
        db,
    )
    data = json.loads(result.output)
    assert data["url"].startswith("https://data.example.com/-/set-password?token=")
    # No doubled slash from the trailing "/" on --base-url.
    assert "com//-" not in data["url"]


def test_invite_duplicate_username_is_exit_1(tmp_path):
    db = str(tmp_path / "a.db")
    run("create", "nia", "-y", "-i", db)
    result = run("invite", "nia", "-y", "-i", db)
    assert result.exit_code == 1
    assert "already taken" in result.output


def test_invite_ttl_hours_flows_through(tmp_path):
    db = str(tmp_path / "a.db")
    # A negative TTL mints an already-expired link — proves the flag reaches
    # the SQL expiry computation.
    result = run("invite", "nia", "--ttl-hours=-1", "-y", "-i", db)
    assert result.exit_code == 0
    row = query(
        db, "SELECT created_at, expires_at FROM datasette_accounts_password_tokens"
    )[0]
    assert row["expires_at"] < row["created_at"]
    # And the printed link is indeed dead.
    assert complete_link(db, token_from(result.output), "whatever-pass1") is None


def test_invite_audit_attributes_cli_user(tmp_path):
    db = str(tmp_path / "a.db")
    run("invite", "nia", "-y", "-i", db)
    row = query(db, "SELECT operation, actor_id FROM datasette_accounts_admin_audit")[0]
    assert row["operation"] == "invite"
    assert row["actor_id"] == f"cli:{getpass.getuser()}"


# --- reset-link ---------------------------------------------------------------


def test_reset_link_mints_working_link_and_audits_actor_override(tmp_path):
    db = str(tmp_path / "a.db")
    run("create", "alice", "--password", "origpass123", "-y", "-i", db)
    result = run("reset-link", "alice", "-y", "-i", db, "--actor", "cli:opsbot")
    assert result.exit_code == 0
    assert "shown once" in result.output
    raw_token = token_from(result.output)

    audit = query(
        db,
        "SELECT operation, actor_id FROM datasette_accounts_admin_audit "
        "WHERE operation = 'mint-reset-link'",
    )
    assert audit == [{"operation": "mint-reset-link", "actor_id": "cli:opsbot"}]
    assert query(db, "SELECT purpose FROM datasette_accounts_password_tokens") == [
        {"purpose": "reset"}
    ]

    # Completing it replaces the password (through the same db layer as HTTP).
    assert complete_link(db, raw_token, "fresh-password-1") is not None
    row = query(db, "SELECT password_hash FROM datasette_accounts_users")[0]
    assert verify_password("fresh-password-1", row["password_hash"])
    assert not verify_password("origpass123", row["password_hash"])


def test_reset_link_json_and_base_url(tmp_path):
    db = str(tmp_path / "a.db")
    run("create", "alice", "-y", "-i", db)
    result = run(
        "reset-link",
        "alice",
        "--base-url",
        "https://data.example.com",
        "--json",
        "-y",
        "-i",
        db,
    )
    data = json.loads(result.output)
    assert data["ok"] is True
    assert data["url"].startswith("https://data.example.com/-/set-password?token=")


def test_reset_link_unknown_user_is_exit_1(tmp_path):
    db = str(tmp_path / "a.db")
    result = run("reset-link", "ghost", "-y", "-i", db)
    assert result.exit_code == 1
    assert "no such user" in result.output
    assert (
        query(db, "SELECT count(*) c FROM datasette_accounts_password_tokens")[0]["c"]
        == 0
    )


def test_reset_link_ttl_hours_flows_through(tmp_path):
    db = str(tmp_path / "a.db")
    run("create", "alice", "-y", "-i", db)
    result = run("reset-link", "alice", "--ttl-hours=-1", "-y", "-i", db)
    assert result.exit_code == 0
    row = query(
        db, "SELECT created_at, expires_at FROM datasette_accounts_password_tokens"
    )[0]
    assert row["expires_at"] < row["created_at"]


def test_reset_link_kills_prior_invite_link(tmp_path):
    db = str(tmp_path / "a.db")
    invite_result = run("invite", "nia", "-y", "-i", db)
    old_token = token_from(invite_result.output)
    run("reset-link", "nia", "-y", "-i", db)
    # One live link per account: the invite token is gone.
    assert query(db, "SELECT purpose FROM datasette_accounts_password_tokens") == [
        {"purpose": "reset"}
    ]
    assert complete_link(db, old_token, "whatever-pass1") is None
