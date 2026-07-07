"""Throwaway seed plugin for the datasette-accounts doc screenshots.

Loaded via ``datasette --plugins-dir`` from ``frontend/scripts/screenshots.mjs``
so the self-contained shots run against deterministic accounts without the Node
driver reimplementing the plugin's create APIs.

It seeds a handful of demo accounts (an admin plus users with varied status:
active / disabled / locked / must-change) directly into the plugin's internal
DB, mirroring how ``tests/test_accounts.py`` inserts users, and one demo session
so the admin "Sessions" drawer has content. Idempotent: skips a DB that is
already seeded. Dev/screenshot-only — NOT shipped.
"""

from datasette import hookimpl
from sqlite_utils import Database

from datasette_accounts import db as accounts_db
from datasette_accounts.internal_migrations import internal_migrations
from datasette_accounts.passwords import hash_password

# The one password every demo account shares — screenshots.mjs logs in with it.
DEMO_PASSWORD = "demo-password"

# Fixed timestamps → deterministic rows. `_FUTURE` keeps the locked user locked
# and the demo session unexpired (so the startup purge never deletes it).
_CREATED = "2026-06-01T12:00:00+00:00"
_FUTURE = "2099-01-01T00:00:00+00:00"
_LAST_SEEN = "2026-07-07T09:32:00+00:00"

# id, username, is_admin, disabled, must_change_password, locked_until
_USERS = [
    ("u-admin", "admin", 1, 0, 0, None),
    ("u-alice", "alice", 0, 0, 0, None),
    ("u-bob", "bob", 0, 1, 0, None),  # disabled
    ("u-carol", "carol", 0, 0, 0, _FUTURE),  # locked
    ("u-dave", "dave", 0, 0, 1, None),  # must change password
]

# A demo active session for alice, so the admin's per-user session drawer shows
# a real row instead of "No active sessions."
_ALICE_SESSION = {
    "token_sha256": "a" * 64,
    "actor_id": "u-alice",
    "created_at": _CREATED,
    "expires_at": _FUTURE,
    "last_seen_at": _LAST_SEEN,
    "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/17.4",
    "ip": "203.0.113.24",
}


@hookimpl
def startup(datasette):
    async def inner():
        internal = datasette.get_internal_database()

        # Ensure our schema exists regardless of plugin startup order.
        def migrate(conn):
            internal_migrations.apply(Database(conn))

        await internal.execute_write_fn(migrate)

        def seed(conn):
            db = Database(conn)
            users = db[accounts_db.USERS]
            if users.exists() and users.count > 0:
                return  # already seeded
            for uid, username, is_admin, disabled, must_change, locked in _USERS:
                db[accounts_db.USERS].insert(
                    {
                        "id": uid,
                        "username": username,
                        "password_hash": hash_password(DEMO_PASSWORD),
                        "is_admin": is_admin,
                        "disabled": disabled,
                        "must_change_password": must_change,
                        "failed_attempts": 5 if locked else 0,
                        "locked_until": locked,
                        "created_at": _CREATED,
                        "updated_at": _CREATED,
                    }
                )
            db[accounts_db.SESSIONS].insert(_ALICE_SESSION)

        await internal.execute_write_fn(seed)

    return inner
