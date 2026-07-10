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


@internal_migrations()
def m002_last_login_at(db: Database):
    # NULL means the account has never had a successful sign-in ("pending" —
    # created but not yet initialised by its owner). Set on each login success.
    db.execute("ALTER TABLE datasette_accounts_users ADD COLUMN last_login_at TEXT")


@internal_migrations()
def m003_capability_grants(db: Database):
    # Admin-managed grants of GLOBAL actions (Datasette actions with no
    # resource_class) to a principal. Resource-scoped actions stay with
    # datasette-acl; this table only ever ALLOWS a global capability.
    #
    # Shape mirrors datasette-acl's `acl` table so the two read consistently:
    # exactly one principal is set per row, enforced by the CHECK, and each
    # principal-kind is deduped by a partial UNIQUE index. `group_id` references
    # acl_groups.id when acl is installed; we store the id and validate on write
    # rather than declaring a cross-plugin foreign key.
    db.executescript(
        """
        CREATE TABLE datasette_accounts_capability_grants (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            action TEXT NOT NULL,
            principal_type TEXT NOT NULL
                CHECK (principal_type IN
                    ('actor', 'group', 'everyone', 'authenticated', 'anonymous')),
            actor_id TEXT,
            group_id INTEGER,
            created_at TEXT NOT NULL,
            created_by TEXT,
            CHECK (
                (principal_type = 'actor'
                    AND actor_id IS NOT NULL AND group_id IS NULL)
                OR (principal_type = 'group'
                    AND group_id IS NOT NULL AND actor_id IS NULL)
                OR (principal_type IN ('everyone', 'authenticated', 'anonymous')
                    AND actor_id IS NULL AND group_id IS NULL)
            )
        );
        CREATE UNIQUE INDEX idx_accounts_grant_actor
            ON datasette_accounts_capability_grants (action, actor_id)
            WHERE principal_type = 'actor';
        CREATE UNIQUE INDEX idx_accounts_grant_group
            ON datasette_accounts_capability_grants (action, group_id)
            WHERE principal_type = 'group';
        CREATE UNIQUE INDEX idx_accounts_grant_public
            ON datasette_accounts_capability_grants (action, principal_type)
            WHERE principal_type IN ('everyone', 'authenticated', 'anonymous');
        """
    )


@internal_migrations()
def m004_site_messages(db: Database):
    # Admin-editable free-text messages surfaced in the running app (a
    # sign-in prompt on the homepage, a "contact X for help" note on the login
    # page, …). One row per known slot key; a cleared message deletes its row,
    # so absence means "no message". The set of valid keys lives in
    # messages.SITE_MESSAGE_SLOTS, not in the schema — bodies are opaque text.
    db.executescript(
        """
        CREATE TABLE datasette_accounts_site_messages (
            key TEXT PRIMARY KEY,
            body TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            updated_by TEXT
        );
        """
    )


@internal_migrations()
def m005_login_audit_reason(db: Database):
    # Record *why* a login attempt landed where it did (the `success` flag is the
    # what; `reason` is the why: bad_password / no_such_user / disabled / locked /
    # reauth / success). Nullable so pre-existing rows stay valid. Indexes back
    # the admin login-attempts view's username/ip filters and the retention purge
    # (DELETE ... WHERE timestamp < ?); the id PK already covers ORDER BY id DESC.
    # The admin_audit table was unindexed too — cover its per-user lookups and
    # purge in the same migration.
    db.execute("ALTER TABLE datasette_accounts_login_audit ADD COLUMN reason TEXT")
    db.executescript(
        """
        CREATE INDEX IF NOT EXISTS idx_accounts_login_audit_username
            ON datasette_accounts_login_audit (username);
        CREATE INDEX IF NOT EXISTS idx_accounts_login_audit_ip
            ON datasette_accounts_login_audit (ip);
        CREATE INDEX IF NOT EXISTS idx_accounts_login_audit_timestamp
            ON datasette_accounts_login_audit (timestamp);
        CREATE INDEX IF NOT EXISTS idx_accounts_admin_audit_target
            ON datasette_accounts_admin_audit (target_id);
        CREATE INDEX IF NOT EXISTS idx_accounts_admin_audit_timestamp
            ON datasette_accounts_admin_audit (timestamp);
        """
    )


@internal_migrations()
def m006_password_tokens(db: Database):
    # One-time "set a password" links. The raw token lives only in the URL the
    # admin copies; we store sha256(token) — same rule as sessions. purpose
    # distinguishes the two flows: 'invite' (account has never had a usable
    # password) vs 'reset' (existing account, sessions revoked on completion).
    db.executescript(
        """
        CREATE TABLE datasette_accounts_password_tokens (
            token_sha256 TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            purpose TEXT NOT NULL CHECK (purpose IN ('invite', 'reset')),
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            created_by TEXT
        );
        CREATE INDEX idx_accounts_pwtokens_user
            ON datasette_accounts_password_tokens (user_id);
        """
    )
