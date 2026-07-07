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
        await internal.execute_write_fn(seed_capabilities)
        await internal.execute_write_fn(seed_messages)

    return inner


# Demo site messages (feature: admin-editable help text). Seeded so the
# Messages admin page shows populated slots, the homepage shows the signed-out
# banner, and the login page shows the help/contact note.
_MESSAGES = {
    "homepage_signed_out": (
        'Sign in to browse the internal datasets. Need access? '
        '<a href="mailto:data-team@example.com">Email the data team</a>.'
    ),
    "login_help": (
        "Trouble signing in? Email "
        '<a href="mailto:data-help@example.com">data-help@example.com</a>.'
    ),
}


def seed_messages(conn):
    """Seed the demo site-message slots (idempotent)."""
    db = Database(conn)
    messages = db[accounts_db.SITE_MESSAGES]
    if messages.exists() and messages.count > 0:
        return  # already seeded
    for key, body in _MESSAGES.items():
        db[accounts_db.SITE_MESSAGES].insert(
            {
                "key": key,
                "body": body,
                "updated_at": _CREATED,
                "updated_by": "u-admin",
            }
        )


def seed_capabilities(conn):
    """Seed a demo acl group + capability grants for the Capabilities shot.

    Grants the global ``datasette-paper-create`` action (registered by the
    installed datasette-paper plugin) to a mix of principals — a named account,
    an acl group, and the "any signed-in user" audience — so the screenshot
    shows all three chip kinds. Idempotent + tolerant of acl not being present.
    """
    db = Database(conn)
    grants = db[accounts_db.CAPABILITY_GRANTS]
    if grants.exists() and grants.count > 0:
        return  # already seeded

    action = "datasette-paper-create"
    rows = [
        {
            "action": action,
            "principal_type": "actor",
            "actor_id": "u-alice",
            "group_id": None,
            "created_at": _CREATED,
            "created_by": "u-admin",
        },
        {
            "action": action,
            "principal_type": "authenticated",
            "actor_id": None,
            "group_id": None,
            "created_at": _CREATED,
            "created_by": "u-admin",
        },
    ]

    # Ensure datasette-acl's tables exist regardless of plugin startup order
    # (so the seeded group grant is deterministic), when acl is installed.
    try:
        from datasette_acl.internal_migrations import internal_migrations as acl_migrations

        acl_migrations.apply(db)
    except ImportError:
        pass

    # A group grant, only when datasette-acl's tables exist.
    if db["acl_groups"].exists():
        conn.execute("INSERT INTO acl_groups (name) VALUES ('Editors')")
        gid = conn.execute(
            "SELECT id FROM acl_groups WHERE name = 'Editors'"
        ).fetchone()[0]
        conn.execute(
            "INSERT INTO acl_actor_groups (actor_id, group_id) VALUES (?, ?)",
            ["u-carol", gid],
        )
        rows.append(
            {
                "action": action,
                "principal_type": "group",
                "actor_id": None,
                "group_id": gid,
                "created_at": _CREATED,
                "created_by": "u-admin",
            }
        )

    grants.insert_all(rows)
