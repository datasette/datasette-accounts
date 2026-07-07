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
