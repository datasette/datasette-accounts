"""Internal-database access layer.

All tables live in Datasette's internal database. Reads use ``execute``;
writes that must be atomic (mutation + audit row in one transaction, or the
last-admin count-then-write guard) use ``execute_write_fn`` with a sync
callback that runs inside a single transaction on the write connection.
"""

import datetime
import json as jsonlib

from ulid import ULID

# Namespaced table names (the internal DB is shared with other plugins).
USERS = "datasette_accounts_users"
SESSIONS = "datasette_accounts_sessions"
LOGIN_AUDIT = "datasette_accounts_login_audit"
ADMIN_AUDIT = "datasette_accounts_admin_audit"

# Single source of truth for "is an admin": used by both the permission grant
# SQL and the last-admin guard so the two definitions can never drift.
ENABLED_ADMIN_PREDICATE = "is_admin = 1 AND disabled = 0"

# Only refresh sessions.last_seen_at when the stored value is older than this,
# to avoid a write on the internal DB's single write connection every request.
LAST_SEEN_THROTTLE_SECONDS = 60


class LastAdminError(Exception):
    """Raised when an operation would remove the final enabled admin."""


class UsernameTakenError(Exception):
    """Raised when creating/renaming to an already-used username."""


def now_iso() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def _iso_minus_days(days: int) -> str:
    return (
        datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=days)
    ).isoformat()


def new_id() -> str:
    return str(ULID())


# --------------------------------------------------------------------------
# Reads
# --------------------------------------------------------------------------


async def get_user_by_username(db, username):
    result = await db.execute(f"SELECT * FROM {USERS} WHERE username = ?", [username])
    row = result.first()
    return dict(row) if row else None


async def get_user_by_id(db, user_id):
    result = await db.execute(f"SELECT * FROM {USERS} WHERE id = ?", [user_id])
    row = result.first()
    return dict(row) if row else None


async def get_session(db, token_sha):
    result = await db.execute(
        f"SELECT * FROM {SESSIONS} WHERE token_sha256 = ?", [token_sha]
    )
    row = result.first()
    return dict(row) if row else None


async def list_users(db):
    result = await db.execute(f"SELECT * FROM {USERS} ORDER BY username")
    return [dict(r) for r in result.rows]


def to_user_row(r):
    """Shape a users row into the UserRow presentation dict (adds `locked`)."""
    return {
        "id": r["id"],
        "username": r["username"],
        "is_admin": bool(r["is_admin"]),
        "disabled": bool(r["disabled"]),
        "must_change_password": bool(r["must_change_password"]),
        "locked": bool(r["locked_until"] and r["locked_until"] > now_iso()),
        "created_at": r["created_at"],
        # NULL until the account's first successful sign-in ("pending").
        "last_login_at": r["last_login_at"],
    }


async def list_sessions_for_user(db, actor_id):
    result = await db.execute(
        f"SELECT * FROM {SESSIONS} WHERE actor_id = ? ORDER BY last_seen_at DESC",
        [actor_id],
    )
    return [dict(r) for r in result.rows]


async def count_enabled_admins(db):
    result = await db.execute(
        f"SELECT COUNT(*) FROM {USERS} WHERE {ENABLED_ADMIN_PREDICATE}"
    )
    return result.single_value()


# --------------------------------------------------------------------------
# Login / session lifecycle
# --------------------------------------------------------------------------


async def record_login_attempt(db, username, ip, success):
    await db.execute_write(
        f"INSERT INTO {LOGIN_AUDIT} (username, ip, timestamp, success) "
        "VALUES (?, ?, ?, ?)",
        [username, ip, now_iso(), 1 if success else 0],
    )


async def register_failed_attempt(db, user_id, lockout_threshold, lockout_minutes):
    """Atomically bump failed_attempts and lock if the threshold is reached.

    Returns the new failed_attempts count.
    """

    def write(conn):
        conn.execute(
            f"UPDATE {USERS} SET failed_attempts = failed_attempts + 1, "
            "updated_at = ? WHERE id = ?",
            [now_iso(), user_id],
        )
        count = conn.execute(
            f"SELECT failed_attempts FROM {USERS} WHERE id = ?", [user_id]
        ).fetchone()[0]
        if lockout_threshold and count >= lockout_threshold:
            locked_until = (
                datetime.datetime.now(datetime.timezone.utc)
                + datetime.timedelta(minutes=lockout_minutes)
            ).isoformat()
            conn.execute(
                f"UPDATE {USERS} SET locked_until = ? WHERE id = ?",
                [locked_until, user_id],
            )
        return count

    return await db.execute_write_fn(write)


async def record_login_success(db, user_id):
    """Clear the lockout counters and stamp last_login_at on a successful login."""
    ts = now_iso()
    await db.execute_write(
        f"UPDATE {USERS} SET failed_attempts = 0, locked_until = NULL, "
        "last_login_at = ?, updated_at = ? WHERE id = ?",
        [ts, ts, user_id],
    )


async def create_session(db, actor_id, token_sha, ttl_days, user_agent, ip):
    ts = now_iso()
    expires_at = (
        datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=ttl_days)
    ).isoformat()
    await db.execute_write(
        f"INSERT INTO {SESSIONS} (token_sha256, actor_id, created_at, expires_at, "
        "last_seen_at, user_agent, ip) VALUES (?, ?, ?, ?, ?, ?, ?)",
        [token_sha, actor_id, ts, expires_at, ts, user_agent, ip],
    )


async def touch_last_seen(db, token_sha, stored_last_seen):
    """Throttled last_seen_at update — skip if refreshed within the window."""
    try:
        last = datetime.datetime.fromisoformat(stored_last_seen)
    except (TypeError, ValueError):
        last = None
    now = datetime.datetime.now(datetime.timezone.utc)
    if last is not None:
        if last.tzinfo is None:
            last = last.replace(tzinfo=datetime.timezone.utc)
        if (now - last).total_seconds() < LAST_SEEN_THROTTLE_SECONDS:
            return
    await db.execute_write(
        f"UPDATE {SESSIONS} SET last_seen_at = ? WHERE token_sha256 = ?",
        [now.isoformat(), token_sha],
    )


async def delete_session(db, token_sha):
    await db.execute_write(
        f"DELETE FROM {SESSIONS} WHERE token_sha256 = ?", [token_sha]
    )


async def delete_expired_sessions(db):
    await db.execute_write(f"DELETE FROM {SESSIONS} WHERE expires_at <= ?", [now_iso()])


async def purge_login_audit(db, retention_days):
    if not retention_days:
        return
    await db.execute_write(
        f"DELETE FROM {LOGIN_AUDIT} WHERE timestamp < ?",
        [_iso_minus_days(retention_days)],
    )


# --------------------------------------------------------------------------
# Admin mutations (each writes an admin_audit row in the same transaction)
# --------------------------------------------------------------------------


def _audit(conn, operation, actor_id, target_id, detail=None):
    conn.execute(
        f"INSERT INTO {ADMIN_AUDIT} (timestamp, operation, actor_id, target_id, detail) "
        "VALUES (?, ?, ?, ?, ?)",
        [
            now_iso(),
            operation,
            actor_id,
            target_id,
            jsonlib.dumps(detail) if detail is not None else None,
        ],
    )


async def create_user(
    db, actor_id, username, password_hash, is_admin, must_change_password
):
    user_id = new_id()
    ts = now_iso()

    def write(conn):
        exists = conn.execute(
            f"SELECT 1 FROM {USERS} WHERE username = ?", [username]
        ).fetchone()
        if exists:
            raise UsernameTakenError(username)
        conn.execute(
            f"INSERT INTO {USERS} (id, username, password_hash, is_admin, disabled, "
            "must_change_password, failed_attempts, locked_until, created_at, updated_at) "
            "VALUES (?, ?, ?, ?, 0, ?, 0, NULL, ?, ?)",
            [
                user_id,
                username,
                password_hash,
                1 if is_admin else 0,
                1 if must_change_password else 0,
                ts,
                ts,
            ],
        )
        _audit(
            conn,
            "create",
            actor_id,
            user_id,
            {"username": username, "is_admin": bool(is_admin)},
        )
        return user_id

    return await db.execute_write_fn(write)


async def reset_password(db, actor_id, target_id, password_hash):
    def write(conn):
        conn.execute(
            f"UPDATE {USERS} SET password_hash = ?, must_change_password = 1, "
            "failed_attempts = 0, locked_until = NULL, updated_at = ? WHERE id = ?",
            [password_hash, now_iso(), target_id],
        )
        conn.execute(f"DELETE FROM {SESSIONS} WHERE actor_id = ?", [target_id])
        _audit(conn, "reset-password", actor_id, target_id)

    await db.execute_write_fn(write)


async def toggle_admin(db, actor_id, target_id):
    def write(conn):
        row = conn.execute(
            f"SELECT is_admin, disabled FROM {USERS} WHERE id = ?", [target_id]
        ).fetchone()
        if not row:
            return None
        is_admin, disabled = row[0], row[1]
        new_value = 0 if is_admin else 1
        # Demoting the last enabled admin is forbidden.
        if is_admin and not disabled:
            _guard_last_admin(conn, exclude_id=target_id)
        conn.execute(
            f"UPDATE {USERS} SET is_admin = ?, updated_at = ? WHERE id = ?",
            [new_value, now_iso(), target_id],
        )
        _audit(conn, "toggle-admin", actor_id, target_id, {"is_admin": bool(new_value)})
        return new_value

    return await db.execute_write_fn(write)


async def disable_user(db, actor_id, target_id):
    def write(conn):
        row = conn.execute(
            f"SELECT {ENABLED_ADMIN_PREDICATE} FROM {USERS} WHERE id = ?", [target_id]
        ).fetchone()
        if row and row[0]:
            _guard_last_admin(conn, exclude_id=target_id)
        conn.execute(
            f"UPDATE {USERS} SET disabled = 1, updated_at = ? WHERE id = ?",
            [now_iso(), target_id],
        )
        conn.execute(f"DELETE FROM {SESSIONS} WHERE actor_id = ?", [target_id])
        _audit(conn, "disable", actor_id, target_id)

    await db.execute_write_fn(write)


async def enable_user(db, actor_id, target_id):
    def write(conn):
        conn.execute(
            f"UPDATE {USERS} SET disabled = 0, updated_at = ? WHERE id = ?",
            [now_iso(), target_id],
        )
        _audit(conn, "enable", actor_id, target_id)

    await db.execute_write_fn(write)


async def delete_user(db, actor_id, target_id):
    def write(conn):
        row = conn.execute(
            f"SELECT {ENABLED_ADMIN_PREDICATE} FROM {USERS} WHERE id = ?", [target_id]
        ).fetchone()
        if row and row[0]:
            _guard_last_admin(conn, exclude_id=target_id)
        conn.execute(f"DELETE FROM {SESSIONS} WHERE actor_id = ?", [target_id])
        conn.execute(f"DELETE FROM {USERS} WHERE id = ?", [target_id])
        _audit(conn, "delete", actor_id, target_id)

    await db.execute_write_fn(write)


async def unlock_user(db, actor_id, target_id):
    def write(conn):
        conn.execute(
            f"UPDATE {USERS} SET failed_attempts = 0, locked_until = NULL, "
            "updated_at = ? WHERE id = ?",
            [now_iso(), target_id],
        )
        _audit(conn, "unlock", actor_id, target_id)

    await db.execute_write_fn(write)


async def revoke_session(db, actor_id, target_id, token_sha):
    def write(conn):
        conn.execute(
            f"DELETE FROM {SESSIONS} WHERE token_sha256 = ? AND actor_id = ?",
            [token_sha, target_id],
        )
        _audit(conn, "revoke-session", actor_id, target_id)

    await db.execute_write_fn(write)


async def logout_everywhere(db, actor_id, target_id):
    def write(conn):
        conn.execute(f"DELETE FROM {SESSIONS} WHERE actor_id = ?", [target_id])
        _audit(conn, "logout-everywhere", actor_id, target_id)

    await db.execute_write_fn(write)


async def change_own_password(db, user_id, password_hash, current_token_sha):
    """Set a new password, clear the forced-change flag, revoke OTHER sessions."""

    def write(conn):
        conn.execute(
            f"UPDATE {USERS} SET password_hash = ?, must_change_password = 0, "
            "failed_attempts = 0, locked_until = NULL, updated_at = ? WHERE id = ?",
            [password_hash, now_iso(), user_id],
        )
        conn.execute(
            f"DELETE FROM {SESSIONS} WHERE actor_id = ? AND token_sha256 != ?",
            [user_id, current_token_sha],
        )
        _audit(conn, "change-own-password", user_id, user_id)

    await db.execute_write_fn(write)


def _guard_last_admin(conn, exclude_id):
    """Raise LastAdminError if no other enabled admin would remain.

    Runs inside the caller's write transaction so the count and the write are
    atomic (no last-two-admins race).
    """
    remaining = conn.execute(
        f"SELECT COUNT(*) FROM {USERS} WHERE {ENABLED_ADMIN_PREDICATE} AND id != ?",
        [exclude_id],
    ).fetchone()[0]
    if remaining == 0:
        raise LastAdminError()
