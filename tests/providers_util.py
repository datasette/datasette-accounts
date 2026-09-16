"""Shared scaffolding for the sign-in provider test files.

Not collected by pytest (no ``test_`` prefix); imported like ``cli_util``.
Everything here drives the app through public routes or the ``db`` helpers a
test needs to set up state — the ``register_provider`` fixture that mounts a
throwaway provider lives in ``conftest.py``.
"""

from datasette.app import Datasette

from datasette_accounts import db
from datasette_accounts.passwords import UNUSABLE_PASSWORD, hash_password
from datasette_accounts.security import SIGN_NAMESPACE
from datasette_accounts.sessions import mint_token, token_sha256

JSON = {"content-type": "application/json"}


async def make_ds(**plugin_config):
    metadata = {}
    if plugin_config:
        metadata = {"plugins": {"datasette-accounts": plugin_config}}
    ds = Datasette(memory=True, metadata=metadata)
    await ds.invoke_startup()
    return ds


async def insert_user(
    ds,
    username,
    *,
    password="password123",
    password_less=False,
    is_admin=False,
    disabled=False,
    must_change_password=False,
    expires_at=None,
    pending=False,
):
    """Insert an account row directly. ``password_less=True`` stores the
    unusable hash (an SSO-only account)."""
    internal = ds.get_internal_database()
    uid = db.new_id()
    ts = db.now_iso()
    pw = UNUSABLE_PASSWORD if password_less else hash_password(password)
    await internal.execute_write(
        f"INSERT INTO {db.USERS} (id, username, password_hash, is_admin, disabled, "
        "must_change_password, failed_attempts, locked_until, created_at, updated_at, "
        "expires_at, pending_approval) "
        "VALUES (?, ?, ?, ?, ?, ?, 0, NULL, ?, ?, ?, ?)",
        [
            uid,
            username,
            pw,
            1 if is_admin else 0,
            1 if disabled else 0,
            1 if must_change_password else 0,
            ts,
            ts,
            expires_at,
            1 if pending else 0,
        ],
    )
    return uid


async def set_setting(ds, key, value):
    """Write one runtime settings row directly (no audit)."""
    internal = ds.get_internal_database()
    await internal.execute_write(
        f"INSERT OR REPLACE INTO {db.SETTINGS} (key, value, updated_at) "
        "VALUES (?, ?, ?)",
        [key, value, db.now_iso()],
    )


async def enable_provider(ds, key, enabled=True):
    await set_setting(ds, f"provider:{key}:enabled", "1" if enabled else "0")


async def set_signups(ds, key, mode):
    await set_setting(ds, f"provider:{key}:signups", mode)


async def session_cookie(ds, uid):
    """Mint a live session for ``uid`` and return the signed cookie value."""
    internal = ds.get_internal_database()
    raw = mint_token()
    await db.create_session(internal, uid, token_sha256(raw), 14, "ua", "1.1.1.1")
    return ds.sign(raw, SIGN_NAMESPACE)


async def session_count(ds):
    internal = ds.get_internal_database()
    rows = await internal.execute(f"SELECT COUNT(*) FROM {db.SESSIONS}")
    return rows.rows[0][0]


async def last_audit_reason(ds):
    internal = ds.get_internal_database()
    rows = await internal.execute(
        f"SELECT reason FROM {db.LOGIN_AUDIT} ORDER BY rowid DESC LIMIT 1"
    )
    return rows.rows[0][0] if rows.rows else None


def cookie_cleared(resp, name):
    return any(
        h.startswith(name + "=") and "Max-Age=0" in h for h in resp._set_cookie_headers
    )


class Args:
    def __init__(self, d):
        self._d = d

    def get(self, key, default=None):
        return self._d.get(key, default)


class FakeRequest:
    """Enough of a Request for make_state / read_state / finish_login."""

    def __init__(self, *, cookies=None, args=None, scheme="https", headers=None):
        self.cookies = cookies or {}
        self.args = Args(args or {})
        self.scheme = scheme
        self.headers = headers or {}


class FakeResponse:
    def __init__(self):
        self.cookies = {}

    def set_cookie(self, name, value="", **kw):
        self.cookies[name] = (value, kw)
