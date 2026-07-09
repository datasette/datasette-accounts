"""Tests for the db.py orchestration layer against a real Datasette internal DB.

These exercise db.py's execute_fn / execute_write_fn wiring end to end — the
dict-shaped return contract, the transactional guards, and the timestamp-driven
lockout/expiry paths. The generated helpers db.py calls are tested in isolation
in test_generated_queries.py.
"""

# Import Datasette first so its plugin entry points load fully before we import
# datasette_accounts submodules (avoids a dev-dependency import cycle).
from datasette.app import Datasette

import datetime
import re

import pytest

from datasette_accounts import db
from datasette_accounts.passwords import UNUSABLE_PASSWORD

# Millisecond ISO-8601 with a +00:00 offset, e.g. 2026-07-07T22:09:25.087+00:00.
TS_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}\+00:00$")


def _parse(ts):
    return datetime.datetime.fromisoformat(ts)


def _now():
    return datetime.datetime.now(datetime.timezone.utc)


async def make_ds():
    ds = Datasette(memory=True)
    await ds.invoke_startup()
    return ds


@pytest.mark.asyncio
async def test_create_user_roundtrip_via_db():
    ds = await make_ds()
    internal = ds.get_internal_database()
    uid = await db.create_user(
        internal,
        actor_id=None,
        username="alice",
        password_hash="h",
        is_admin=True,
        must_change_password=False,
    )
    user = await db.get_user_by_username(internal, "alice")
    assert user["id"] == uid
    assert user["is_admin"] == 1
    assert TS_RE.match(user["created_at"])
    # Duplicate username is rejected atomically.
    with pytest.raises(db.UsernameTakenError):
        await db.create_user(
            internal,
            actor_id=None,
            username="alice",
            password_hash="h",
            is_admin=False,
            must_change_password=False,
        )


@pytest.mark.asyncio
async def test_lockout_sets_future_locked_until():
    ds = await make_ds()
    internal = ds.get_internal_database()
    uid = await db.create_user(
        internal,
        actor_id=None,
        username="alice",
        password_hash="h",
        is_admin=False,
        must_change_password=False,
    )
    count = 0
    for _ in range(3):
        count = await db.register_failed_attempt(
            internal, uid, lockout_threshold=3, lockout_minutes=15
        )
    assert count == 3
    user = await db.get_user_by_username(internal, "alice")
    assert user["locked_until"] is not None
    assert _parse(user["locked_until"]) > _now()
    # to_user_row reflects the live lock via a now_iso() comparison.
    assert db.to_user_row(user)["locked"] is True
    # Unlocking clears it.
    await db.unlock_user(internal, actor_id=None, target_id=uid)
    user = await db.get_user_by_username(internal, "alice")
    assert user["locked_until"] is None
    assert db.to_user_row(user)["locked"] is False


@pytest.mark.asyncio
async def test_session_lifecycle_and_expiry_purge():
    ds = await make_ds()
    internal = ds.get_internal_database()
    # A live session (7 days) and an already-expired one (negative TTL).
    await db.create_session(internal, "u1", "live", 7, "UA", "1.1.1.1")
    await db.create_session(internal, "u1", "dead", -1, "UA", "1.1.1.1")
    live = await db.get_session(internal, "live")
    assert _parse(live["expires_at"]) > _now()
    await db.delete_expired_sessions(internal)
    assert await db.get_session(internal, "dead") is None
    assert await db.get_session(internal, "live") is not None


@pytest.mark.asyncio
async def test_touch_last_seen_throttle():
    ds = await make_ds()
    internal = ds.get_internal_database()
    await db.create_session(internal, "u1", "tok", 7, "UA", "1.1.1.1")
    before = (await db.get_session(internal, "tok"))["last_seen_at"]
    # A fresh stored value is within the throttle window → no write.
    await db.touch_last_seen(internal, "tok", db.now_iso())
    assert (await db.get_session(internal, "tok"))["last_seen_at"] == before
    # A stale stored value (well beyond the window) → last_seen advances.
    stale = (_now() - datetime.timedelta(hours=1)).isoformat(timespec="milliseconds")
    await db.touch_last_seen(internal, "tok", stale)
    after = (await db.get_session(internal, "tok"))["last_seen_at"]
    assert after >= before
    assert TS_RE.match(after)


# --------------------------------------------------------------------------
# Password tokens (invite links / reset links)
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_create_invited_user_has_unusable_password_and_live_token():
    ds = await make_ds()
    internal = ds.get_internal_database()
    uid = await db.create_invited_user(
        internal,
        actor_id="admin1",
        username="alice",
        is_admin=False,
        token_sha="tok1",
        ttl_hours=72,
    )
    user = await db.get_user_by_id(internal, uid)
    assert user["password_hash"] == UNUSABLE_PASSWORD
    assert user["must_change_password"] == 0
    token = await db.get_password_token(internal, "tok1")
    assert token is not None
    assert token["user_id"] == uid
    assert token["purpose"] == "invite"
    assert token["username"] == "alice"
    assert _parse(token["expires_at"]) > _now()
    # Duplicate username is rejected atomically (no orphaned token row).
    with pytest.raises(db.UsernameTakenError):
        await db.create_invited_user(
            internal,
            actor_id="admin1",
            username="alice",
            is_admin=False,
            token_sha="tok2",
            ttl_hours=72,
        )
    assert await db.get_password_token(internal, "tok2") is None


@pytest.mark.asyncio
async def test_use_password_token_claims_once_sets_password_and_revokes_sessions():
    ds = await make_ds()
    internal = ds.get_internal_database()
    uid = await db.create_invited_user(
        internal,
        actor_id=None,
        username="bob",
        is_admin=False,
        token_sha="tok1",
        ttl_hours=72,
    )
    await db.create_session(internal, uid, "sess1", 7, "UA", "1.1.1.1")
    assert await db.get_session(internal, "sess1") is not None

    result_uid = await db.use_password_token(internal, "tok1", "newhash")
    assert result_uid == uid

    user = await db.get_user_by_id(internal, uid)
    assert user["password_hash"] == "newhash"
    assert user["must_change_password"] == 0
    # All the user's sessions are revoked as part of completing the link.
    assert await db.get_session(internal, "sess1") is None
    # Audit row: actor and target are both the user themselves.
    audit = await db.list_admin_audit(internal, target_id=uid)
    ops = [row["operation"] for row in audit]
    assert "set-password-via-link" in ops
    set_row = next(r for r in audit if r["operation"] == "set-password-via-link")
    assert set_row["actor_id"] == uid
    assert set_row["target_id"] == uid

    # Second claim of the same (now-deleted) token fails.
    assert await db.use_password_token(internal, "tok1", "otherhash") is None
    user = await db.get_user_by_id(internal, uid)
    assert user["password_hash"] == "newhash"  # unchanged by the failed claim


@pytest.mark.asyncio
async def test_expired_token_not_claimable():
    ds = await make_ds()
    internal = ds.get_internal_database()
    uid = await db.create_invited_user(
        internal,
        actor_id=None,
        username="carol",
        is_admin=False,
        token_sha="tok1",
        ttl_hours=-1,
    )
    assert await db.get_password_token(internal, "tok1") is None
    assert await db.use_password_token(internal, "tok1", "newhash") is None
    user = await db.get_user_by_id(internal, uid)
    assert user["password_hash"] == UNUSABLE_PASSWORD


@pytest.mark.asyncio
async def test_mint_password_token_invalidates_prior_link():
    ds = await make_ds()
    internal = ds.get_internal_database()
    uid = await db.create_invited_user(
        internal,
        actor_id=None,
        username="dave",
        is_admin=False,
        token_sha="tok1",
        ttl_hours=72,
    )
    await db.mint_password_token(
        internal,
        actor_id="admin1",
        target_id=uid,
        purpose="invite",
        token_sha="tok2",
        ttl_hours=72,
    )
    assert await db.get_password_token(internal, "tok1") is None
    row = await db.get_password_token(internal, "tok2")
    assert row is not None and row["user_id"] == uid

    audit = await db.list_admin_audit(internal, target_id=uid)
    assert "mint-invite-link" in [r["operation"] for r in audit]


@pytest.mark.asyncio
async def test_mint_reset_link_audits_distinct_operation():
    ds = await make_ds()
    internal = ds.get_internal_database()
    uid = await db.create_user(
        internal,
        actor_id=None,
        username="erin",
        password_hash="h",
        is_admin=False,
        must_change_password=False,
    )
    await db.mint_password_token(
        internal,
        actor_id="admin1",
        target_id=uid,
        purpose="reset",
        token_sha="tok1",
        ttl_hours=24,
    )
    token = await db.get_password_token(internal, "tok1")
    assert token["purpose"] == "reset"
    audit = await db.list_admin_audit(internal, target_id=uid)
    assert "mint-reset-link" in [r["operation"] for r in audit]


@pytest.mark.asyncio
async def test_disable_delete_reset_kill_outstanding_tokens():
    ds = await make_ds()
    internal = ds.get_internal_database()

    uid1 = await db.create_user(
        internal, None, "frank", "h", is_admin=False, must_change_password=False
    )
    await db.mint_password_token(
        internal, None, uid1, "reset", "tok-disable", ttl_hours=24
    )
    await db.disable_user(internal, actor_id=None, target_id=uid1)
    assert await db.get_password_token(internal, "tok-disable") is None

    uid2 = await db.create_user(
        internal, None, "grace", "h", is_admin=False, must_change_password=False
    )
    await db.mint_password_token(
        internal, None, uid2, "reset", "tok-delete", ttl_hours=24
    )
    await db.delete_user(internal, actor_id=None, target_id=uid2)
    assert await db.get_password_token(internal, "tok-delete") is None

    uid3 = await db.create_user(
        internal, None, "henry", "h", is_admin=False, must_change_password=False
    )
    await db.mint_password_token(
        internal, None, uid3, "reset", "tok-reset", ttl_hours=24
    )
    await db.reset_password(internal, actor_id=None, target_id=uid3, password_hash="h2")
    assert await db.get_password_token(internal, "tok-reset") is None


@pytest.mark.asyncio
async def test_purge_expired_password_tokens_via_db():
    ds = await make_ds()
    internal = ds.get_internal_database()
    await db.create_invited_user(
        internal,
        actor_id=None,
        username="ivy",
        is_admin=False,
        token_sha="live",
        ttl_hours=72,
    )
    await db.create_invited_user(
        internal,
        actor_id=None,
        username="jack",
        is_admin=False,
        token_sha="dead",
        ttl_hours=-1,
    )
    await db.purge_expired_password_tokens(internal)
    count = (
        await internal.execute(f"SELECT COUNT(*) FROM {db.PASSWORD_TOKENS}")
    ).single_value()
    assert count == 1
    remaining = (
        await internal.execute(f"SELECT token_sha256 FROM {db.PASSWORD_TOKENS}")
    ).single_value()
    assert remaining == "live"
