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
        pending_approval=0,
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
        pending_approval=0,
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
        conn, username="alice", ip="1.2.3.4", success=1, reason="success", provider=None
    )
    gen.insert_login_attempt(
        conn,
        username="bob",
        ip=None,
        success=0,
        reason="bad_password",
        provider="echo",
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
# Password tokens
# ==========================================================================


def test_insert_select_and_claim_password_token(conn):
    gen.insert_user(
        conn,
        id="u1",
        username="alice",
        password_hash="!",
        is_admin=0,
        must_change_password=0,
        pending_approval=0,
    )
    gen.insert_password_token(
        conn,
        token_sha256="tok1",
        user_id="u1",
        purpose="invite",
        ttl_hours=72,
        created_by=None,
    )
    row = gen.select_password_token(conn, token_sha256="tok1")
    assert row is not None
    assert row.user_id == "u1"
    assert row.purpose == "invite"
    assert row.username == "alice"
    assert _parse(row.expires_at) > _now()
    # Claim-by-delete: RETURNING user_id on the live row...
    assert gen.delete_password_token(conn, token_sha256="tok1") == "u1"
    # ...and nothing left to claim a second time (single-use).
    assert gen.delete_password_token(conn, token_sha256="tok1") is None
    assert gen.select_password_token(conn, token_sha256="tok1") is None


def test_expired_password_token_not_selectable_or_claimable(conn):
    gen.insert_user(
        conn,
        id="u1",
        username="bob",
        password_hash="!",
        is_admin=0,
        must_change_password=0,
        pending_approval=0,
    )
    gen.insert_password_token(
        conn,
        token_sha256="tok1",
        user_id="u1",
        purpose="reset",
        ttl_hours=-1,
        created_by=None,
    )
    assert gen.select_password_token(conn, token_sha256="tok1") is None
    # The DELETE itself requires expires_at > now, so an expired-but-unpurged
    # row is never claimable either.
    assert gen.delete_password_token(conn, token_sha256="tok1") is None


def test_purge_expired_password_tokens_removes_only_expired_resets(conn):
    for uid, name in [("u1", "carol"), ("u2", "dan"), ("u3", "eve")]:
        gen.insert_user(
            conn,
            id=uid,
            username=name,
            password_hash="!",
            is_admin=0,
            must_change_password=0,
            pending_approval=0,
        )
    for tok, uid, purpose, ttl in [
        ("live-invite", "u1", "invite", 72),
        # Kept even though expired: the lapsed invite is the only durable
        # record that the account never got a usable password.
        ("dead-invite", "u2", "invite", -1),
        ("live-reset", "u3", "reset", 24),
    ]:
        gen.insert_password_token(
            conn,
            token_sha256=tok,
            user_id=uid,
            purpose=purpose,
            ttl_hours=ttl,
            created_by=None,
        )
    # Second token for u3 would violate one-live-link, so give the dead reset
    # its own user id — purge doesn't care whether the account exists.
    gen.insert_password_token(
        conn,
        token_sha256="dead-reset",
        user_id="u4",
        purpose="reset",
        ttl_hours=-1,
        created_by=None,
    )
    gen.purge_expired_password_tokens(conn)
    remaining = conn.execute(
        "SELECT token_sha256 FROM datasette_accounts_password_tokens ORDER BY 1"
    ).fetchall()
    assert [r[0] for r in remaining] == ["dead-invite", "live-invite", "live-reset"]


def test_list_password_token_meta_hides_dead_resets_keeps_dead_invites(conn):
    for uid, name in [("u1", "fay"), ("u2", "gil"), ("u3", "hal")]:
        gen.insert_user(
            conn,
            id=uid,
            username=name,
            password_hash="!",
            is_admin=0,
            must_change_password=0,
            pending_approval=0,
        )
    for tok, uid, purpose, ttl, creator in [
        ("t1", "u1", "invite", 72, "u3"),
        ("t2", "u2", "invite", -1, "cli:ops"),
        ("t3", "u3", "reset", -1, None),
    ]:
        gen.insert_password_token(
            conn,
            token_sha256=tok,
            user_id=uid,
            purpose=purpose,
            ttl_hours=ttl,
            created_by=creator,
        )
    meta = {m.user_id: m for m in gen.list_password_token_meta(conn)}
    # Expired invite stays visible; the expired reset is hidden.
    assert set(meta) == {"u1", "u2"}
    # Creator resolves to a username when it is an account id...
    assert meta["u1"].created_by_username == "hal"
    # ...and stays raw for synthetic actors.
    assert meta["u2"].created_by == "cli:ops"
    assert meta["u2"].created_by_username is None


def test_delete_password_tokens_for_user(conn):
    gen.insert_user(
        conn,
        id="u1",
        username="dave",
        password_hash="!",
        is_admin=0,
        must_change_password=0,
        pending_approval=0,
    )
    gen.insert_password_token(
        conn,
        token_sha256="tok1",
        user_id="u1",
        purpose="invite",
        ttl_hours=72,
        created_by=None,
    )
    gen.delete_password_tokens_for_user(conn, user_id="u1")
    assert gen.select_password_token(conn, token_sha256="tok1") is None


def test_set_password_from_token(conn):
    gen.insert_user(
        conn,
        id="u1",
        username="erin",
        password_hash="!",
        is_admin=0,
        must_change_password=1,
        pending_approval=0,
    )
    gen.set_password_from_token(conn, password_hash="newhash", user_id="u1")
    row = gen.select_user_by_id(conn, user_id="u1")
    assert row.password_hash == "newhash"
    assert row.must_change_password == 0


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
        pending_approval=0,
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
        pending_approval=0,
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
        provider="password",
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
    gen.insert_login_attempt(
        conn, username="new", ip=None, success=1, reason=None, provider=None
    )
    gen.purge_login_audit(conn, retention_days=30)
    remaining = gen.list_login_attempts(conn, username=None, ip=None, limit=10)
    assert [r.username for r in remaining] == ["new"]


# ==========================================================================
# Account expiry — SQL-side timestamp normalization (see plans/account-expiry)
# ==========================================================================


@pytest.mark.parametrize(
    "value,expected",
    [
        # Bare date → midnight UTC, canonical millisecond form.
        ("2099-01-02", "2099-01-02T00:00:00.000+00:00"),
        # Seconds-precision, no offset (read as UTC).
        ("2099-01-02T03:04:05", "2099-01-02T03:04:05.000+00:00"),
        # Z suffix.
        ("2099-01-02T03:04:05Z", "2099-01-02T03:04:05.000+00:00"),
        # A +HH:MM offset is shifted to UTC.
        ("2099-01-02T03:04:05+02:00", "2099-01-02T01:04:05.000+00:00"),
        # A -HH:MM offset too.
        ("2099-01-02T03:04:05-05:30", "2099-01-02T08:34:05.000+00:00"),
    ],
)
def test_normalize_future_timestamp_canonicalizes(conn, value, expected):
    assert gen.normalize_future_timestamp(conn, value=value) == expected


@pytest.mark.parametrize(
    "value",
    [
        "not a date",
        "2099-13-45",  # parseable-looking garbage
        "",
        "2020-01-01",  # in the past
        "2020-01-01T00:00:00Z",  # in the past, with offset
    ],
)
def test_normalize_future_timestamp_rejects_garbage_and_past(conn, value):
    assert gen.normalize_future_timestamp(conn, value=value) is None


def test_expiry_in_days_is_now_plus_days(conn):
    value = gen.expiry_in_days(conn, days=30)
    assert TS_RE.match(value)
    ahead_days = (_parse(value) - _now()).total_seconds() / 86400
    assert 29.99 < ahead_days < 30.01


def test_set_user_expiry_writes_and_clears(conn):
    gen.insert_user(
        conn,
        id="u1",
        username="alice",
        password_hash="h",
        is_admin=0,
        must_change_password=0,
        pending_approval=0,
    )
    gen.set_user_expiry(conn, expires_at="2099-01-02T00:00:00.000+00:00", user_id="u1")
    row = gen.select_user_by_id(conn, user_id="u1")
    assert row.expires_at == "2099-01-02T00:00:00.000+00:00"
    assert TS_RE.match(row.updated_at)
    # NULL clears.
    gen.set_user_expiry(conn, expires_at=None, user_id="u1")
    assert gen.select_user_by_id(conn, user_id="u1").expires_at is None
