"""Tests for the generated query helpers (sql/_queries_generated.py).

These exercise the codegen output directly against a raw sqlite3 connection
with the migrated schema — no Datasette — covering the shapes codegen is
responsible for: typed round trips, RETURNING, the collapsed optional-filter
query, and the SQL-generated timestamps (format + relative deadlines).

db.py's orchestration over these helpers is tested in test_db.py.
"""

# Import Datasette first so its plugin entry points load fully before we import
# datasette_accounts submodules (avoids a dev-dependency import cycle).
from datasette.app import Datasette  # noqa: F401

import datetime
import re

import pytest
from sqlite_utils import Database

from datasette_accounts import db
from datasette_accounts.internal_migrations import internal_migrations
from datasette_accounts.sql import _queries_generated as gen

# Millisecond ISO-8601 with a +00:00 offset, e.g. 2026-07-07T22:09:25.087+00:00.
TS_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}\+00:00$")


def _parse(ts):
    return datetime.datetime.fromisoformat(ts)


def _now():
    return datetime.datetime.now(datetime.timezone.utc)


@pytest.fixture
def conn():
    """Raw sqlite3 connection with the full migrated schema."""
    sdb = Database(memory=True)
    internal_migrations.apply(sdb)
    return sdb.conn


# ==========================================================================
# Round trips
# ==========================================================================


def test_insert_and_select_user(conn):
    gen.insert_user(
        conn,
        id="u1",
        username="alice",
        password_hash="hash",
        is_admin=1,
        must_change_password=0,
    )
    by_name = gen.select_user_by_username(conn, username="alice")
    by_id = gen.select_user_by_id(conn, user_id="u1")
    assert by_name is not None and by_id is not None
    assert by_name == by_id
    assert by_name.username == "alice"
    assert by_name.is_admin == 1
    assert by_name.password_hash == "hash"
    # A miss returns None, not a raise.
    assert gen.select_user_by_username(conn, username="nobody") is None


def test_value_and_existence_helpers(conn):
    gen.insert_user(
        conn,
        id="u1",
        username="alice",
        password_hash="h",
        is_admin=1,
        must_change_password=0,
    )
    assert gen.count_enabled_admins(conn) == 1
    assert gen.count_other_enabled_admins(conn, exclude_id="u1") == 0
    assert gen.username_exists(conn, username="alice") == 1
    assert gen.username_exists(conn, username="nobody") is None
    assert gen.user_id_exists(conn, user_id="u1") == 1
    assert gen.select_user_is_enabled_admin(conn, user_id="u1") == 1
    state = gen.select_user_admin_state(conn, user_id="u1")
    assert state is not None
    assert (state.is_admin, state.disabled) == (1, 0)


def test_optional_login_filters(conn):
    gen.insert_login_attempt(
        conn, username="alice", ip="1.2.3.4", success=1, reason="success"
    )
    gen.insert_login_attempt(
        conn, username="bob", ip=None, success=0, reason="bad_password"
    )
    assert len(gen.list_login_attempts(conn, username=None, ip=None, limit=10)) == 2
    only_alice = gen.list_login_attempts(conn, username="alice", ip=None, limit=10)
    assert [r.username for r in only_alice] == ["alice"]
    by_ip = gen.list_login_attempts(conn, username=None, ip="1.2.3.4", limit=10)
    assert [r.username for r in by_ip] == ["alice"]
    # Filters AND-combine: mismatched pair yields nothing.
    assert gen.list_login_attempts(conn, username="bob", ip="1.2.3.4", limit=10) == []


def test_capability_grant_returning_is_idempotent(conn):
    first = gen.insert_capability_grant(
        conn,
        action="a",
        principal_type="everyone",
        actor_id=None,
        group_id=None,
        created_by="u1",
    )
    assert first == 1  # RETURNING id on insert
    dup = gen.insert_capability_grant(
        conn,
        action="a",
        principal_type="everyone",
        actor_id=None,
        group_id=None,
        created_by="u1",
    )
    assert dup is None  # OR IGNORE → no row returned


def test_site_message_delete_returning(conn):
    gen.upsert_site_message(conn, key="homepage", body="hi", updated_by="u1")
    assert gen.select_site_message(conn, key="homepage") == "hi"
    gen.upsert_site_message(conn, key="homepage", body="bye", updated_by="u1")
    assert gen.select_site_message(conn, key="homepage") == "bye"
    assert gen.delete_site_message(conn, key="homepage") == "homepage"
    assert gen.delete_site_message(conn, key="homepage") is None  # already gone


# ==========================================================================
# SQL-generated timestamps
# ==========================================================================


def test_now_iso_format_matches_sql_clock(conn):
    # db.now_iso() (Python) and the SQL clock must produce the same shape so
    # they compare lexicographically.
    assert TS_RE.match(db.now_iso())
    sql_now = conn.execute(
        "SELECT strftime('%Y-%m-%dT%H:%M:%f','now') || '+00:00'"
    ).fetchone()[0]
    assert TS_RE.match(sql_now)


def test_insert_user_stamps_matching_created_updated(conn):
    gen.insert_user(
        conn,
        id="u1",
        username="alice",
        password_hash="h",
        is_admin=0,
        must_change_password=0,
    )
    row = gen.select_user_by_id(conn, user_id="u1")
    assert row is not None
    assert TS_RE.match(row.created_at)
    # 'now' is stable within one statement → created_at == updated_at.
    assert row.created_at == row.updated_at
    # And it's within a few seconds of the wall clock.
    assert abs((_parse(row.created_at) - _now()).total_seconds()) < 10


def test_set_locked_until_is_now_plus_minutes(conn):
    gen.insert_user(
        conn,
        id="u1",
        username="alice",
        password_hash="h",
        is_admin=0,
        must_change_password=0,
    )
    gen.set_locked_until(conn, lockout_minutes=15, user_id="u1")
    row = gen.select_user_by_id(conn, user_id="u1")
    assert row is not None and row.locked_until is not None
    assert TS_RE.match(row.locked_until)
    delta = (_parse(row.locked_until) - _now()).total_seconds()
    assert 15 * 60 - 30 < delta < 15 * 60 + 30  # ~15 minutes ahead


def test_insert_session_expiry_is_now_plus_days(conn):
    gen.insert_session(
        conn,
        token_sha256="tok",
        actor_id="u1",
        ttl_days=7,
        user_agent="UA",
        ip="1.2.3.4",
    )
    row = gen.select_session(conn, token_sha256="tok")
    assert row is not None
    assert row.created_at == row.last_seen_at
    for ts in (row.created_at, row.expires_at):
        assert TS_RE.match(ts)
    ahead_days = (
        _parse(row.expires_at) - _parse(row.created_at)
    ).total_seconds() / 86400
    assert 6.99 < ahead_days < 7.01


def test_purge_login_audit_respects_retention(conn):
    # A row well past the retention window, inserted directly with an old stamp.
    conn.execute(
        "INSERT INTO datasette_accounts_login_audit (username, ip, timestamp, success) "
        "VALUES ('old', NULL, '2000-01-01T00:00:00.000+00:00', 0)"
    )
    gen.insert_login_attempt(conn, username="new", ip=None, success=1, reason=None)
    gen.purge_login_audit(conn, retention_days=30)
    remaining = gen.list_login_attempts(conn, username=None, ip=None, limit=10)
    assert [r.username for r in remaining] == ["new"]
