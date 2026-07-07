"""Internal-database schema (append-only migrations).

Namespace ``datasette-accounts.internal`` — distinct from
``datasette-user-profiles.internal`` so migration bookkeeping never interleaves.
Never edit a shipped migration; add ``m002_…`` etc. instead.
"""

from sqlite_utils import Database
from sqlite_migrate import Migrations

internal_migrations = Migrations("datasette-accounts.internal")


@internal_migrations()
def m001_initial(db: Database):
    db.executescript(
        """
        CREATE TABLE datasette_accounts_users (
            id TEXT PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            is_admin INTEGER NOT NULL DEFAULT 0,
            disabled INTEGER NOT NULL DEFAULT 0,
            must_change_password INTEGER NOT NULL DEFAULT 0,
            failed_attempts INTEGER NOT NULL DEFAULT 0,
            locked_until TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );

        CREATE TABLE datasette_accounts_sessions (
            token_sha256 TEXT PRIMARY KEY,
            actor_id TEXT NOT NULL,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            last_seen_at TEXT NOT NULL,
            user_agent TEXT,
            ip TEXT
        );
        CREATE INDEX idx_accounts_sessions_actor
            ON datasette_accounts_sessions (actor_id);

        CREATE TABLE datasette_accounts_login_audit (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            ip TEXT,
            timestamp TEXT NOT NULL,
            success INTEGER NOT NULL
        );

        CREATE TABLE datasette_accounts_admin_audit (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            operation TEXT NOT NULL,
            actor_id TEXT,
            target_id TEXT,
            detail TEXT
        );
        """
    )
