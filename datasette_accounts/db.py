"""Internal-database access layer.

All tables live in Datasette's internal database. This module is pure
orchestration over the typed query helpers generated from ``sql/queries.sql``
(see ``sql/_queries_generated.py``): reads run the ``conn``-first helpers
inside ``execute_fn`` (a read connection); writes that must be atomic (mutation
+ audit row in one transaction, or the last-admin count-then-write guard) run
them inside ``execute_write_fn`` (a single transaction on the write
connection). The generated helpers return dataclasses; this layer converts them
back to plain dicts so callers (routes, page data) keep their existing shape.

A few queries touch datasette-acl's tables, which aren't in our schema and may
be absent at runtime, so codegen can't type them — those stay hand-written here
(``acl_available``, ``list_acl_groups``, ``list_capability_grants``).
"""

import dataclasses
import datetime
import json as jsonlib

from ulid import ULID

from .passwords import UNUSABLE_PASSWORD
from .sql import _queries_generated as gen

# Namespaced table names (the internal DB is shared with other plugins). Kept
# for the hand-written acl-touching queries below; the generated helpers hard-
# code the same names (codegen needs literal SQL).
USERS = "datasette_accounts_users"
SESSIONS = "datasette_accounts_sessions"
LOGIN_AUDIT = "datasette_accounts_login_audit"
ADMIN_AUDIT = "datasette_accounts_admin_audit"
CAPABILITY_GRANTS = "datasette_accounts_capability_grants"
SITE_MESSAGES = "datasette_accounts_site_messages"
PASSWORD_TOKENS = "datasette_accounts_password_tokens"
SETTINGS = "datasette_accounts_settings"

# The one settings key this ticket uses — see plans/self-registration.
REGISTRATION_ENABLED_KEY = "registration_enabled"

# datasette-acl tables we reference (softly) for the "group" principal. We never
# write them — acl owns them — but we join them to resolve group membership +
# names when acl is installed. Absent → the group principal is simply disabled.
ACL_GROUPS = "acl_groups"
ACL_ACTOR_GROUPS = "acl_actor_groups"

# Principal kinds a capability grant may target (mirrors datasette-acl).
PUBLIC_PRINCIPALS = ("everyone", "authenticated", "anonymous")
PRINCIPAL_TYPES = ("actor", "group", *PUBLIC_PRINCIPALS)

# Single source of truth for "is an admin": used by both the permission grant
# SQL and the last-admin guard so the two definitions can never drift. The
# same literal text is duplicated (codegen needs literal SQL) inside
# countEnabledAdmins / countOtherEnabledAdmins / selectUserIsEnabledAdmin in
# sql/queries.sql — see test_predicate_matches_queries_sql, which greps for
# this exact string so the two copies can't drift silently.
ENABLED_ADMIN_PREDICATE = (
    "is_admin = 1 AND disabled = 0 AND (expires_at IS NULL OR expires_at > "
    "strftime('%Y-%m-%dT%H:%M:%f','now') || '+00:00')"
)

# Only refresh sessions.last_seen_at when the stored value is older than this,
# to avoid a write on the internal DB's single write connection every request.
LAST_SEEN_THROTTLE_SECONDS = 60


class LastAdminError(Exception):
    """Raised when an operation would remove the final enabled admin."""


class UsernameTakenError(Exception):
    """Raised when creating/renaming to an already-used username."""


class InvalidGrantError(Exception):
    """Raised when a capability grant references an unknown actor/group or a
    principal kind that isn't available (e.g. a group while acl is absent)."""


class InvalidExpiryError(Exception):
    """Raised when a requested account expiry is unparseable, not in the
    future, or a non-positive day count."""


class NotPendingError(Exception):
    """Raised when rejecting an account that is not awaiting approval — a
    mis-aimed reject must never delete an active user."""


def now_iso() -> str:
    """Current UTC time as millisecond ISO-8601 with a +00:00 offset.

    Byte-identical to the generated queries' SQL clock
    (``strftime('%Y-%m-%dT%H:%M:%f','now') || '+00:00'``), so timestamps written
    in SQL and this "now" — used only for the read-side ``locked_until`` /
    ``expires_at`` comparisons — sort and compare lexicographically.
    """
    return datetime.datetime.now(datetime.timezone.utc).isoformat(
        timespec="milliseconds"
    )


def new_id() -> str:
    return str(ULID())


def _as_dict(row):
    """Generated dataclass row → plain dict (or None), matching the old
    ``dict(sqlite_row)`` shape callers expect."""
    return dataclasses.asdict(row) if row is not None else None


# --------------------------------------------------------------------------
# Reads
# --------------------------------------------------------------------------


async def get_user_by_username(db, username):
    row = await db.execute_fn(
        lambda conn: gen.select_user_by_username(conn, username=username)
    )
    return _as_dict(row)


async def get_user_by_id(db, user_id):
    row = await db.execute_fn(lambda conn: gen.select_user_by_id(conn, user_id=user_id))
    return _as_dict(row)


async def get_session(db, token_sha):
    row = await db.execute_fn(
        lambda conn: gen.select_session(conn, token_sha256=token_sha)
    )
    return _as_dict(row)


async def list_users(db):
    rows = await db.execute_fn(gen.list_users)
    return [dataclasses.asdict(r) for r in rows]


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
        # NULL = never expires. Same lexicographic now_iso() comparison as `locked`.
        "expires_at": r["expires_at"],
        "expired": bool(r["expires_at"] and r["expires_at"] <= now_iso()),
        # True for a self-registered account awaiting an admin's verdict — see
        # plans/self-registration. Admin-created accounts are never pending.
        "pending_approval": bool(r["pending_approval"]),
    }


async def list_user_rows(db):
    """UserRow presentation dicts for the admin surfaces (page + list API).

    The single assembly point for admin user rows, so the page shell and the
    refresh API can't drift: ``to_user_row`` plus the one-time-link state —
    ``invited`` (live ``purpose='invite'`` token), ``invite_expired`` (the
    invite lapsed unused — the account still has no usable password), and the
    ``link_*`` metadata behind the badges' tooltips. Deliberately not users
    columns: the token *is* the state, so completion / expiry / re-mint keep
    the flags correct for free.
    """

    def read(conn):
        meta = {m.user_id: m for m in gen.list_password_token_meta(conn)}
        now = now_iso()
        rows = []
        for u in gen.list_users(conn):
            m = meta.get(u.id)
            live = bool(m and m.expires_at > now)
            rows.append(
                {
                    **to_user_row(dataclasses.asdict(u)),
                    "invited": bool(m and m.purpose == "invite" and live),
                    "invite_expired": bool(m and m.purpose == "invite" and not live),
                    "link_purpose": m.purpose if m else None,
                    "link_expires_at": m.expires_at if m else None,
                    "link_created_by": (
                        (m.created_by_username or m.created_by) if m else None
                    ),
                }
            )
        return rows

    return await db.execute_fn(read)


async def list_sessions_for_user(db, actor_id):
    rows = await db.execute_fn(
        lambda conn: gen.list_sessions_for_user(conn, actor_id=actor_id)
    )
    return [dataclasses.asdict(r) for r in rows]


async def count_enabled_admins(db):
    return await db.execute_fn(gen.count_enabled_admins)


# Cap the admin-audit read (shell `accounts audit`, admin trail page) so a
# large trail can't be dumped in a single query; callers' own `limit`/filters
# narrow further.
ADMIN_AUDIT_MAX = 500


async def list_admin_audit(db, target_id=None, operation=None, limit=200):
    """Most-recent-first admin-audit rows, optionally filtered to one target
    user and/or one operation (AND-combined, exact). Resolves actor/target
    usernames (None when the account no longer exists, or the actor is
    synthetic, e.g. "root" / "cli:$USER"). `limit` is clamped to
    ADMIN_AUDIT_MAX.
    """
    clamped = max(1, min(limit, ADMIN_AUDIT_MAX))
    rows = await db.execute_fn(
        lambda conn: gen.list_admin_audit(
            conn,
            target_id=target_id or None,
            operation=operation or None,
            limit=clamped,
        )
    )
    return [dataclasses.asdict(r) for r in rows]


async def list_admin_audit_operations(db):
    """Distinct operation names recorded in the admin-audit trail, sorted."""
    rows = await db.execute_fn(gen.list_admin_audit_operations)
    return [r.operation for r in rows]


async def purge_admin_audit(db, retention_days):
    if not retention_days:
        return
    # SQL computes the cutoff as `now - retention_days`.
    await db.execute_write_fn(
        lambda conn: gen.purge_admin_audit(conn, retention_days=retention_days)
    )


# --------------------------------------------------------------------------
# Login / session lifecycle
# --------------------------------------------------------------------------


async def record_login_attempt(db, username, ip, success, reason=None):
    await db.execute_write_fn(
        lambda conn: gen.insert_login_attempt(
            conn,
            username=username,
            ip=ip,
            success=1 if success else 0,
            reason=reason,
        )
    )


# Cap the admin login-attempts view so a large audit table can't be dumped in one
# query; the UI filters (username/ip) narrow further.
LOGIN_ATTEMPTS_MAX = 500


async def list_login_attempts(db, username=None, ip=None, limit=200):
    """Most-recent-first login-audit rows, optionally filtered by exact
    username and/or ip (AND-combined). `limit` is clamped to LOGIN_ATTEMPTS_MAX.
    """
    clamped = max(1, min(limit, LOGIN_ATTEMPTS_MAX))
    rows = await db.execute_fn(
        lambda conn: gen.list_login_attempts(
            # Empty string means "no filter" (matches the old truthiness check).
            conn,
            username=username or None,
            ip=ip or None,
            limit=clamped,
        )
    )
    return [dataclasses.asdict(r) for r in rows]


async def register_failed_attempt(db, user_id, lockout_threshold, lockout_minutes):
    """Atomically bump failed_attempts and lock if the threshold is reached.

    Returns the new failed_attempts count.
    """

    def write(conn):
        gen.bump_failed_attempts(conn, user_id=user_id)
        count = gen.select_failed_attempts(conn, user_id=user_id)
        if lockout_threshold and count >= lockout_threshold:
            # SQL computes `now + lockout_minutes`.
            gen.set_locked_until(conn, lockout_minutes=lockout_minutes, user_id=user_id)
        return count

    return await db.execute_write_fn(write)


async def record_login_success(db, user_id):
    """Clear the lockout counters and stamp last_login_at on a successful login."""
    await db.execute_write_fn(
        lambda conn: gen.record_login_success(conn, user_id=user_id)
    )


async def create_session(db, actor_id, token_sha, ttl_days, user_agent, ip):
    # SQL stamps created_at/last_seen_at = now and expires_at = now + ttl_days.
    await db.execute_write_fn(
        lambda conn: gen.insert_session(
            conn,
            token_sha256=token_sha,
            actor_id=actor_id,
            ttl_days=ttl_days,
            user_agent=user_agent,
            ip=ip,
        )
    )


async def touch_last_seen(db, token_sha, stored_last_seen):
    """Throttled last_seen_at update — skip if refreshed within the window.

    The throttle stays in Python (comparing the already-loaded ``last_seen_at``
    against now) so a fresh session avoids touching the internal DB's single
    write connection at all; the update itself stamps ``now`` in SQL.
    """
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
    await db.execute_write_fn(
        lambda conn: gen.touch_last_seen(conn, token_sha256=token_sha)
    )


async def delete_session(db, token_sha):
    await db.execute_write_fn(
        lambda conn: gen.delete_session(conn, token_sha256=token_sha)
    )


async def delete_expired_sessions(db):
    await db.execute_write_fn(gen.delete_expired_sessions)


async def purge_login_audit(db, retention_days):
    if not retention_days:
        return
    # SQL computes the cutoff as `now - retention_days`.
    await db.execute_write_fn(
        lambda conn: gen.purge_login_audit(conn, retention_days=retention_days)
    )


# --------------------------------------------------------------------------
# Admin mutations (each writes an admin_audit row in the same transaction)
# --------------------------------------------------------------------------


def _audit(conn, operation, actor_id, target_id, detail=None):
    gen.insert_admin_audit(
        conn,
        operation=operation,
        actor_id=actor_id,
        target_id=target_id,
        detail=jsonlib.dumps(detail) if detail is not None else None,
    )


async def create_user(
    db, actor_id, username, password_hash, is_admin, must_change_password
):
    user_id = new_id()

    def write(conn):
        if gen.username_exists(conn, username=username):
            raise UsernameTakenError(username)
        gen.insert_user(
            conn,
            id=user_id,
            username=username,
            password_hash=password_hash,
            is_admin=1 if is_admin else 0,
            must_change_password=1 if must_change_password else 0,
            pending_approval=0,
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
        gen.reset_password(conn, password_hash=password_hash, user_id=target_id)
        gen.delete_sessions_for_actor(conn, actor_id=target_id)
        gen.delete_password_tokens_for_user(conn, user_id=target_id)
        _audit(conn, "reset-password", actor_id, target_id)

    await db.execute_write_fn(write)


async def toggle_admin(db, actor_id, target_id):
    def write(conn):
        state = gen.select_user_admin_state(conn, user_id=target_id)
        if state is None:
            return None
        is_admin, disabled = state.is_admin, state.disabled
        new_value = 0 if is_admin else 1
        # Demoting the last enabled admin is forbidden.
        if is_admin and not disabled:
            _guard_last_admin(conn, exclude_id=target_id)
        gen.set_user_admin(conn, is_admin=new_value, user_id=target_id)
        _audit(conn, "toggle-admin", actor_id, target_id, {"is_admin": bool(new_value)})
        return new_value

    return await db.execute_write_fn(write)


async def disable_user(db, actor_id, target_id):
    def write(conn):
        if gen.select_user_is_enabled_admin(conn, user_id=target_id):
            _guard_last_admin(conn, exclude_id=target_id)
        gen.set_user_disabled(conn, disabled=1, user_id=target_id)
        gen.delete_sessions_for_actor(conn, actor_id=target_id)
        gen.delete_password_tokens_for_user(conn, user_id=target_id)
        _audit(conn, "disable", actor_id, target_id)

    await db.execute_write_fn(write)


async def enable_user(db, actor_id, target_id):
    def write(conn):
        gen.set_user_disabled(conn, disabled=0, user_id=target_id)
        _audit(conn, "enable", actor_id, target_id)

    await db.execute_write_fn(write)


async def delete_user(db, actor_id, target_id):
    def write(conn):
        if gen.select_user_is_enabled_admin(conn, user_id=target_id):
            _guard_last_admin(conn, exclude_id=target_id)
        gen.delete_sessions_for_actor(conn, actor_id=target_id)
        gen.delete_password_tokens_for_user(conn, user_id=target_id)
        gen.delete_user(conn, user_id=target_id)
        _audit(conn, "delete", actor_id, target_id)

    await db.execute_write_fn(write)


async def unlock_user(db, actor_id, target_id):
    def write(conn):
        gen.clear_lockout(conn, user_id=target_id)
        _audit(conn, "unlock", actor_id, target_id)

    await db.execute_write_fn(write)


async def set_user_expiry(db, actor_id, target_id, *, at=None, in_days=None):
    """Set, extend, or clear an account's expiry deadline.

    At most one of ``at`` (an ISO-ish timestamp string) and ``in_days`` may be
    given; both ``None`` clears the deadline. The stored value is resolved
    entirely in SQL inside the write transaction — ``at`` is parsed, shifted
    to UTC, and checked to be in the future by ``normalizeFutureTimestamp``
    (``InvalidExpiryError`` on NULL), ``in_days`` by ``expiryInDays`` (the
    ``in_days > 0`` check is the one non-datetime validation, done here).

    Setting (not clearing) a deadline on the last enabled admin raises
    ``LastAdminError`` — you may not put a fuse on the only admin (an expired
    last admin is an admin-UI lockout short of the CLI). Returns ``False``
    when the target id doesn't exist (like ``mint_password_token``), else the
    stored value (``None`` for a clear).
    """
    if at is not None and in_days is not None:
        raise ValueError("at most one of at / in_days may be given")
    if in_days is not None and in_days <= 0:
        raise InvalidExpiryError("in_days must be a positive number of days")

    def write(conn):
        if not gen.user_id_exists(conn, user_id=target_id):
            return False
        if at is not None:
            value = gen.normalize_future_timestamp(conn, value=at)
            if value is None:
                raise InvalidExpiryError(
                    "expiry must be a valid timestamp in the future"
                )
        elif in_days is not None:
            value = gen.expiry_in_days(conn, days=in_days)
        else:
            value = None
        if value is not None and gen.select_user_is_enabled_admin(
            conn, user_id=target_id
        ):
            _guard_last_admin(conn, exclude_id=target_id)
        gen.set_user_expiry(conn, expires_at=value, user_id=target_id)
        if value is not None:
            _audit(conn, "set-expiry", actor_id, target_id, {"expires_at": value})
        else:
            _audit(conn, "clear-expiry", actor_id, target_id)
        return value

    return await db.execute_write_fn(write)


async def revoke_session(db, actor_id, target_id, token_sha):
    def write(conn):
        gen.delete_session_for_actor(conn, token_sha256=token_sha, actor_id=target_id)
        _audit(conn, "revoke-session", actor_id, target_id)

    await db.execute_write_fn(write)


async def logout_everywhere(db, actor_id, target_id):
    def write(conn):
        gen.delete_sessions_for_actor(conn, actor_id=target_id)
        _audit(conn, "logout-everywhere", actor_id, target_id)

    await db.execute_write_fn(write)


async def logout_other_sessions(db, user_id, current_token_sha):
    """Delete all of a user's sessions except the current one (self-service).

    Unlike the admin-only ``logout_everywhere``, the user pressing the button
    stays signed in. Audited with the user as both actor and target.
    """

    def write(conn):
        gen.delete_other_sessions_for_actor(
            conn, actor_id=user_id, token_sha256=current_token_sha
        )
        _audit(conn, "logout-others", user_id, user_id)

    await db.execute_write_fn(write)


async def change_own_password(db, user_id, password_hash, current_token_sha):
    """Set a new password, clear the forced-change flag, revoke OTHER sessions."""

    def write(conn):
        gen.change_own_password(conn, password_hash=password_hash, user_id=user_id)
        gen.delete_other_sessions_for_actor(
            conn, actor_id=user_id, token_sha256=current_token_sha
        )
        _audit(conn, "change-own-password", user_id, user_id)

    await db.execute_write_fn(write)


def _guard_last_admin(conn, exclude_id):
    """Raise LastAdminError if no other enabled admin would remain.

    Runs inside the caller's write transaction so the count and the write are
    atomic (no last-two-admins race).
    """
    if gen.count_other_enabled_admins(conn, exclude_id=exclude_id) == 0:
        raise LastAdminError()


# --------------------------------------------------------------------------
# Password tokens (one-time invite / reset links — see plans/invite-links)
# --------------------------------------------------------------------------


async def create_invited_user(db, actor_id, username, is_admin, token_sha, ttl_hours):
    """Create an account with no usable password plus its invite token.

    One write transaction: the account (UNUSABLE_PASSWORD, so it can't log in
    until the link is used), the token, and the audit row.
    """
    user_id = new_id()

    def write(conn):
        if gen.username_exists(conn, username=username):
            raise UsernameTakenError(username)
        gen.insert_user(
            conn,
            id=user_id,
            username=username,
            password_hash=UNUSABLE_PASSWORD,
            is_admin=1 if is_admin else 0,
            must_change_password=0,
            pending_approval=0,
        )
        gen.insert_password_token(
            conn,
            token_sha256=token_sha,
            user_id=user_id,
            purpose="invite",
            ttl_hours=ttl_hours,
            created_by=actor_id,
        )
        _audit(
            conn,
            "invite",
            actor_id,
            user_id,
            {"username": username, "is_admin": bool(is_admin)},
        )
        return user_id

    return await db.execute_write_fn(write)


async def mint_password_token(db, actor_id, target_id, purpose, token_sha, ttl_hours):
    """Mint a fresh token for an existing account, killing any prior one.

    One live link per account regardless of purpose — minting always deletes
    whatever token (invite or reset) the account already had. Returns False
    (nothing minted, no audit row) when the account doesn't exist — a token
    for a phantom user would still be claimable (the claim-by-delete doesn't
    join users), producing a no-op password write and a mis-attributed audit
    row. The check runs inside the write transaction, so it can't race the
    mint.
    """
    operation = "mint-invite-link" if purpose == "invite" else "mint-reset-link"

    def write(conn):
        if not gen.user_id_exists(conn, user_id=target_id):
            return False
        gen.delete_password_tokens_for_user(conn, user_id=target_id)
        gen.insert_password_token(
            conn,
            token_sha256=token_sha,
            user_id=target_id,
            purpose=purpose,
            ttl_hours=ttl_hours,
            created_by=actor_id,
        )
        _audit(conn, operation, actor_id, target_id)
        return True

    return await db.execute_write_fn(write)


async def use_password_token(db, token_sha, password_hash):
    """Claim a token and set the new password. Returns the user id, or None.

    Claim-by-delete inside the write transaction: the DELETE itself requires
    an unexpired row, so a double-submit race or an expired-but-unpurged link
    both simply find nothing to claim. On a successful claim, every session
    for the account is revoked — a link that could set the password must also
    be able to force a re-login.
    """

    def write(conn):
        user_id = gen.delete_password_token(conn, token_sha256=token_sha)
        if user_id is None:
            return None
        gen.set_password_from_token(conn, password_hash=password_hash, user_id=user_id)
        gen.delete_sessions_for_actor(conn, actor_id=user_id)
        _audit(conn, "set-password-via-link", user_id, user_id)
        return user_id

    return await db.execute_write_fn(write)


async def get_password_token(db, token_sha):
    """The live (non-expired) token row for the GET set-password page, or None."""
    row = await db.execute_fn(
        lambda conn: gen.select_password_token(conn, token_sha256=token_sha)
    )
    return _as_dict(row)


async def purge_expired_password_tokens(db):
    await db.execute_write_fn(gen.purge_expired_password_tokens)


# --------------------------------------------------------------------------
# Capability grants (global-action grants managed by admins — F1)
# --------------------------------------------------------------------------


async def acl_available(db):
    """True when datasette-acl's group tables exist in the internal DB.

    Gates the "group" principal everywhere: without acl there are no groups to
    reference, so the resolver skips the group clause and the UI hides the
    group picker.

    Hand-written (not codegen): introspects sqlite_master for acl tables that
    aren't part of this plugin's schema.
    """
    result = await db.execute(
        "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name IN (?, ?)",
        [ACL_GROUPS, ACL_ACTOR_GROUPS],
    )
    return result.single_value() == 2


async def list_acl_groups(db):
    """Non-deleted acl groups as [{id, name}] for the group picker (or []).

    Hand-written (not codegen): reads acl_groups, which is owned by
    datasette-acl and absent from this plugin's schema.
    """
    if not await acl_available(db):
        return []
    result = await db.execute(
        f"SELECT id, name FROM {ACL_GROUPS} WHERE deleted IS NULL ORDER BY name"
    )
    return [{"id": r["id"], "name": r["name"]} for r in result.rows]


async def list_capability_grants(db, actions=None):
    """All capability grants, newest first, with resolved display labels.

    Joins users (for actor grants → username) and, when acl is present,
    acl_groups (for group grants → group name). ``actions`` optionally filters
    to a set/list of action names.

    Hand-written (not codegen): the group-name subquery references acl_groups
    only when acl is installed (a runtime-conditional join), and the optional
    ``action IN (...)`` list is variable-length — neither fits codegen's static
    schema model.
    """
    has_acl = await acl_available(db)
    group_name = (
        f"(SELECT name FROM {ACL_GROUPS} WHERE id = g.group_id)" if has_acl else "NULL"
    )
    sql = f"""
        SELECT g.id, g.action, g.principal_type, g.actor_id, g.group_id,
               g.created_at, g.created_by,
               (SELECT username FROM {USERS} WHERE id = g.actor_id) AS actor_username,
               {group_name} AS group_name
        FROM {CAPABILITY_GRANTS} g
    """
    params = []
    if actions is not None:
        actions = list(actions)
        if not actions:
            return []
        placeholders = ", ".join("?" for _ in actions)
        sql += f" WHERE g.action IN ({placeholders})"
        params = actions
    sql += " ORDER BY g.action, g.id DESC"
    result = await db.execute(sql, params)
    return [dict(r) for r in result.rows]


async def grant_capability(
    db, actor_id, *, action, principal_type, target_actor_id=None, group_id=None
):
    """Insert a capability grant (idempotent). Returns True if a row was added.

    Validates the principal inside the write transaction: an actor grant must
    name an existing account; a group grant must name a live acl group (and acl
    must be installed). Duplicate grants are a no-op (partial unique indexes).
    """
    if principal_type not in PRINCIPAL_TYPES:
        raise InvalidGrantError(f"unknown principal type: {principal_type}")
    # Normalise: only the matching id column is stored.
    actor_val = target_actor_id if principal_type == "actor" else None
    group_val = group_id if principal_type == "group" else None
    if principal_type == "actor" and not actor_val:
        raise InvalidGrantError("actor grant requires an account")
    if principal_type == "group" and group_val is None:
        raise InvalidGrantError("group grant requires a group")

    def write(conn):
        if principal_type == "actor":
            # select_user_by_id (not user_id_exists) so a pending account —
            # invisible to acl and unable to log in — can also be excluded as
            # a grant target (plans/self-registration). One-bit stricter than
            # a plain existence check, so no separate query is needed.
            target_user = gen.select_user_by_id(conn, user_id=actor_val)
            if target_user is None:
                raise InvalidGrantError("unknown account")
            if target_user.pending_approval:
                raise InvalidGrantError("account is awaiting approval")
        elif principal_type == "group":
            # acl tables are hand-checked: they're not in our schema and may be
            # absent, so we can't codegen these lookups.
            has_groups = conn.execute(
                "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?",
                [ACL_GROUPS],
            ).fetchone()
            if not has_groups:
                raise InvalidGrantError(
                    "groups are unavailable (datasette-acl not installed)"
                )
            if not conn.execute(
                f"SELECT 1 FROM {ACL_GROUPS} WHERE id = ? AND deleted IS NULL",
                [group_val],
            ).fetchone():
                raise InvalidGrantError("unknown group")
        new_id = gen.insert_capability_grant(
            conn,
            action=action,
            principal_type=principal_type,
            actor_id=actor_val,
            group_id=group_val,
            created_by=actor_id,
        )
        if new_id is None:
            return False  # already granted — no-op, no audit noise
        _audit(
            conn,
            "grant-capability",
            actor_id,
            actor_val,
            {
                "action": action,
                "principal_type": principal_type,
                "group_id": group_val,
            },
        )
        return True

    return await db.execute_write_fn(write)


async def revoke_capability(db, actor_id, grant_id):
    """Delete a capability grant by id. Returns True if a row was removed."""

    def write(conn):
        row = gen.select_capability_grant(conn, grant_id=grant_id)
        if row is None:
            return False
        gen.delete_capability_grant(conn, grant_id=grant_id)
        _audit(
            conn,
            "revoke-capability",
            actor_id,
            row.actor_id,
            {
                "action": row.action,
                "principal_type": row.principal_type,
                "group_id": row.group_id,
            },
        )
        return True

    return await db.execute_write_fn(write)


# --------------------------------------------------------------------------
# Site messages
# --------------------------------------------------------------------------


async def get_site_messages(db):
    """All stored site messages as ``{key: body}`` (only non-empty rows exist)."""
    rows = await db.execute_fn(gen.list_site_messages)
    return {r.key: r.body for r in rows}


async def get_site_message(db, key):
    """The stored body for one slot, or ``None`` when it has never been set."""
    return await db.execute_fn(lambda conn: gen.select_site_message(conn, key=key))


async def set_site_message(db, actor_id, key, body):
    """Upsert (or, for a blank body, clear) one site-message slot.

    A blank body deletes the row so "unset" is always the absence of a row.
    Records an admin-audit entry in the same transaction. Returns the stored
    body (``""`` when cleared). Raises ``ValueError`` for an unknown slot key.
    """
    from . import messages

    if not messages.is_slot(key):
        raise ValueError(f"unknown message slot: {key}")
    body = (body or "").strip()

    def write(conn):
        if body:
            gen.upsert_site_message(conn, key=key, body=body, updated_by=actor_id)
            _audit(conn, "set-message", actor_id, None, {"key": key})
        else:
            # RETURNING key is non-empty only when a row existed.
            if gen.delete_site_message(conn, key=key) is not None:
                _audit(conn, "clear-message", actor_id, None, {"key": key})
        return body

    return await db.execute_write_fn(write)


# --------------------------------------------------------------------------
# Self-registration (see plans/self-registration)
# --------------------------------------------------------------------------


async def get_registration_enabled(db):
    """Whether ``/-/register`` is currently open.

    Mirrors the site_messages absence-is-default convention: a missing row
    means signups are closed, so a fresh install needs no seed row. Read
    per-request by the register page, the submit endpoint, and (later) the
    login page — a single-row PK lookup, same cost as ``login_help``.
    """
    value = await db.execute_fn(
        lambda conn: gen.select_setting(conn, key=REGISTRATION_ENABLED_KEY)
    )
    return value == "1"


async def set_registration_enabled(db, actor_id, enabled):
    """Flip the self-registration toggle. Returns the new (bool) state.

    One write tx: upsert ``'1'`` to turn on, delete the row to turn off
    (absence = off, matching the blank-clears convention used by site
    messages). No-op — no audit row — when the setting is already in the
    requested state, so repeat flips from the UI don't spam the audit trail.
    """

    def write(conn):
        current = gen.select_setting(conn, key=REGISTRATION_ENABLED_KEY) == "1"
        if bool(enabled) == current:
            return current
        if enabled:
            gen.upsert_setting(
                conn, key=REGISTRATION_ENABLED_KEY, value="1", updated_by=actor_id
            )
            _audit(conn, "enable-registration", actor_id, None)
        else:
            gen.delete_setting(conn, key=REGISTRATION_ENABLED_KEY)
            _audit(conn, "disable-registration", actor_id, None)
        return bool(enabled)

    return await db.execute_write_fn(write)


async def get_provider_enabled(db, key):
    """Whether the auth provider ``key`` is currently enabled.

    Settings key ``provider:{key}:enabled`` ('1' / '0'). An absent row means the
    built-in password provider is enabled and every external provider is
    disabled — installing a provider package changes nothing until an admin
    flips it (plans/auth-providers/02-design.md §7). Read per-request by
    ``providers.provider_gate`` (and, in core-03, by ``finish_login``'s external
    re-check), a single-row PK lookup like the other runtime settings.
    """
    value = await db.execute_fn(
        lambda conn: gen.select_setting(conn, key=f"provider:{key}:enabled")
    )
    if value is None:
        return key == "password"
    return value == "1"


async def register_user(db, username, password_hash, ip):
    """Self-service registration: insert a pending account + audit row.

    One write tx: the same ``UsernameTakenError`` check as ``create_user``,
    then insert with ``pending_approval = 1`` and ``must_change_password = 0``
    (the visitor chose their own password, so there is nothing to force a
    change on). Audited as ``"register"`` with ``actor_id = None`` — no admin
    acted — and the target is the new account; detail carries the username
    and originating IP (the per-IP throttle in a later ticket reuses this
    same row via ``login_audit`` instead, but the admin-audit detail is kept
    for the audit-trail read).
    """
    user_id = new_id()

    def write(conn):
        if gen.username_exists(conn, username=username):
            raise UsernameTakenError(username)
        gen.insert_user(
            conn,
            id=user_id,
            username=username,
            password_hash=password_hash,
            is_admin=0,
            must_change_password=0,
            pending_approval=1,
        )
        _audit(conn, "register", None, user_id, {"username": username, "ip": ip})
        return user_id

    return await db.execute_write_fn(write)


async def count_pending_users(db):
    """How many self-registered accounts are awaiting a verdict.

    Drives the admin homepage banner and the registration queue cap.
    """
    return await db.execute_fn(gen.count_pending_users)


async def count_recent_registrations(db, ip):
    """Registration attempts (successful or refused) from `ip` in the last day.

    Backs the per-IP signup throttle. ``None`` (no resolvable client IP)
    counts as 0 — the queue cap still applies, and NULL would never equal a
    stored ip anyway.
    """
    if ip is None:
        return 0
    return await db.execute_fn(lambda conn: gen.count_recent_registrations(conn, ip=ip))


async def approve_user(db, actor_id, target_id):
    """Approve a pending account: flip ``pending_approval`` off + audit.

    Returns ``False`` when the target id doesn't exist (the
    ``mint_password_token`` pattern), else ``True``. Approving an account
    that isn't pending is an idempotent no-op — the flag is already the
    requested value, so no audit noise (matching ``set_registration_enabled``).
    The existence check runs inside the write transaction, so it can't race
    a concurrent reject.
    """

    def write(conn):
        user = gen.select_user_by_id(conn, user_id=target_id)
        if user is None:
            return False
        if user.pending_approval:
            gen.set_user_approved(conn, user_id=target_id)
            _audit(conn, "approve", actor_id, target_id, {"username": user.username})
        return True

    return await db.execute_write_fn(write)


async def reject_user(db, actor_id, target_id):
    """Reject a pending account: delete the row + audit, keeping the username.

    Returns ``False`` when the target id doesn't exist; raises
    ``NotPendingError`` when the account exists but isn't awaiting approval —
    a mis-aimed reject must never delete an active user (the route maps this
    to a 400). A pending account has no sessions or password tokens, but
    delete them defensively like ``delete_user`` does. The audit detail
    carries the username because the row is gone — keep the name findable.
    """

    def write(conn):
        user = gen.select_user_by_id(conn, user_id=target_id)
        if user is None:
            return False
        if not user.pending_approval:
            raise NotPendingError(target_id)
        gen.delete_sessions_for_actor(conn, actor_id=target_id)
        gen.delete_password_tokens_for_user(conn, user_id=target_id)
        gen.delete_user(conn, user_id=target_id)
        _audit(conn, "reject", actor_id, target_id, {"username": user.username})
        return True

    return await db.execute_write_fn(write)
