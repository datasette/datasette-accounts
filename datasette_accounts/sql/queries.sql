-- schema: ../../schema.db

-- Named queries for datasette-accounts.
--
-- Edit here, then run `just codegen-queries` to regenerate `_queries.sql.json`
-- (the codegen IR) and `_queries_generated.py` (typed Python helpers).
-- `just check-queries-fresh` is the CI gate.
--
-- solite codegen syntax (subset):
--     -- name: foo                     -- :rows by default → list[Row]
--     -- name: foo :rows -> UserRow    -- list[UserRow] using a named class
--     -- name: foo :row  -> UserRow    -- UserRow | None
--     -- name: foo :value              -- scalar | None
--     -- name: foo                     -- Void for INSERT/UPDATE/DELETE
--
-- Parameter sigils:
--     $foo::text                       -- non-null text → str
--     $foo::text::                     -- nullable text → str | None
--     $foo::integer                    -- int (non-null)
--
-- Timestamps are generated in SQL, not passed in: "now" is
--     strftime('%Y-%m-%dT%H:%M:%f','now') || '+00:00'
-- which is byte-identical to Python's
--     datetime.now(timezone.utc).isoformat(timespec="milliseconds")
-- (millisecond ISO-8601 with a +00:00 offset), so the values sort and compare
-- lexicographically against db.now_iso() everywhere. Relative deadlines use a
-- printf-built modifier, e.g. printf('+%d minutes', $n) → '+15 minutes'.
-- 'now' is stable within a single statement, so paired columns written together
-- (created_at/updated_at, last_login_at/updated_at) get the identical instant.
--
-- Table names are hard-coded here (codegen needs literal SQL); the `{USERS}`
-- etc. constants in db.py cover the few hand-written queries that touch
-- datasette-acl tables not present in this schema.
--
-- Multi-statement orchestration (audit-in-same-tx, last-admin guard, lockout
-- bump-then-check) lives in db.py — codegen emits one helper per query block.

-- ============================================================================
-- Users (reads)
--
-- Every user-returning query selects the same explicit column set so the
-- generated ``UserRow`` dataclass has one shape (matching the old ``SELECT *``).
-- ============================================================================

-- name: selectUserByUsername :row -> UserRow
SELECT id, username, password_hash, is_admin, disabled, must_change_password,
       failed_attempts, locked_until, created_at, updated_at, last_login_at,
       expires_at
FROM datasette_accounts_users
WHERE username = $username::text;

-- name: selectUserById :row -> UserRow
SELECT id, username, password_hash, is_admin, disabled, must_change_password,
       failed_attempts, locked_until, created_at, updated_at, last_login_at,
       expires_at
FROM datasette_accounts_users
WHERE id = $user_id::text;

-- name: listUsers :rows -> UserRow
SELECT id, username, password_hash, is_admin, disabled, must_change_password,
       failed_attempts, locked_until, created_at, updated_at, last_login_at,
       expires_at
FROM datasette_accounts_users
ORDER BY username;

-- Mirrors db.ENABLED_ADMIN_PREDICATE (kept byte-identical — see
-- test_predicate_matches_queries_sql). expires_at is checked here, not just
-- `disabled`, so an expired admin stops counting as one everywhere at once.
-- name: countEnabledAdmins :value
SELECT COUNT(*) FROM datasette_accounts_users
WHERE is_admin = 1 AND disabled = 0 AND (expires_at IS NULL OR expires_at >
    strftime('%Y-%m-%dT%H:%M:%f','now') || '+00:00');

-- Count of OTHER enabled admins — the last-admin guard (excludes the target).
-- Mirrors db.ENABLED_ADMIN_PREDICATE (see test_predicate_matches_queries_sql).
-- name: countOtherEnabledAdmins :value
SELECT COUNT(*) FROM datasette_accounts_users
WHERE is_admin = 1 AND disabled = 0 AND (expires_at IS NULL OR expires_at >
    strftime('%Y-%m-%dT%H:%M:%f','now') || '+00:00') AND id != $exclude_id::text;

-- Does this username already exist? (1 or None) — create/rename collision check.
-- name: usernameExists :value
SELECT 1 FROM datasette_accounts_users WHERE username = $username::text;

-- Does an account with this id exist? (1 or None) — actor-grant validation.
-- name: userIdExists :value
SELECT 1 FROM datasette_accounts_users WHERE id = $user_id::text;

-- Is the target an enabled admin? (1/0 or None) — drives the last-admin guard
-- in disable/delete. Mirrors ENABLED_ADMIN_PREDICATE in db.py (see
-- test_predicate_matches_queries_sql).
-- name: selectUserIsEnabledAdmin :value
SELECT is_admin = 1 AND disabled = 0 AND (expires_at IS NULL OR expires_at >
    strftime('%Y-%m-%dT%H:%M:%f','now') || '+00:00')
FROM datasette_accounts_users WHERE id = $user_id::text;

-- Current admin/disabled flags for the toggle-admin guard.
-- name: selectUserAdminState :row -> AdminStateRow
SELECT is_admin, disabled FROM datasette_accounts_users WHERE id = $user_id::text;

-- Current failed-attempts count, read back inside the lockout transaction.
-- name: selectFailedAttempts :value
SELECT failed_attempts FROM datasette_accounts_users WHERE id = $user_id::text;

-- ============================================================================
-- Users (writes)
-- ============================================================================

-- name: insertUser
INSERT INTO datasette_accounts_users
    (id, username, password_hash, is_admin, disabled, must_change_password,
     failed_attempts, locked_until, created_at, updated_at)
VALUES ($id::text, $username::text, $password_hash::text, $is_admin::integer, 0,
        $must_change_password::integer, 0, NULL,
        strftime('%Y-%m-%dT%H:%M:%f', 'now') || '+00:00',
        strftime('%Y-%m-%dT%H:%M:%f', 'now') || '+00:00');

-- name: bumpFailedAttempts
UPDATE datasette_accounts_users
SET failed_attempts = failed_attempts + 1,
    updated_at = strftime('%Y-%m-%dT%H:%M:%f', 'now') || '+00:00'
WHERE id = $user_id::text;

-- Lock the account until `lockout_minutes` from now.
-- name: setLockedUntil
UPDATE datasette_accounts_users
SET locked_until =
    strftime('%Y-%m-%dT%H:%M:%f', 'now', printf('%+d minutes', $lockout_minutes::integer))
    || '+00:00'
WHERE id = $user_id::text;

-- name: clearLockout
UPDATE datasette_accounts_users
SET failed_attempts = 0, locked_until = NULL,
    updated_at = strftime('%Y-%m-%dT%H:%M:%f', 'now') || '+00:00'
WHERE id = $user_id::text;

-- name: recordLoginSuccess
UPDATE datasette_accounts_users
SET failed_attempts = 0, locked_until = NULL,
    last_login_at = strftime('%Y-%m-%dT%H:%M:%f', 'now') || '+00:00',
    updated_at = strftime('%Y-%m-%dT%H:%M:%f', 'now') || '+00:00'
WHERE id = $user_id::text;

-- name: resetPassword
UPDATE datasette_accounts_users
SET password_hash = $password_hash::text, must_change_password = 1,
    failed_attempts = 0, locked_until = NULL,
    updated_at = strftime('%Y-%m-%dT%H:%M:%f', 'now') || '+00:00'
WHERE id = $user_id::text;

-- name: changeOwnPassword
UPDATE datasette_accounts_users
SET password_hash = $password_hash::text, must_change_password = 0,
    failed_attempts = 0, locked_until = NULL,
    updated_at = strftime('%Y-%m-%dT%H:%M:%f', 'now') || '+00:00'
WHERE id = $user_id::text;

-- name: setUserAdmin
UPDATE datasette_accounts_users
SET is_admin = $is_admin::integer,
    updated_at = strftime('%Y-%m-%dT%H:%M:%f', 'now') || '+00:00'
WHERE id = $user_id::text;

-- name: setUserDisabled
UPDATE datasette_accounts_users
SET disabled = $disabled::integer,
    updated_at = strftime('%Y-%m-%dT%H:%M:%f', 'now') || '+00:00'
WHERE id = $user_id::text;

-- name: deleteUser
DELETE FROM datasette_accounts_users WHERE id = $user_id::text;

-- ============================================================================
-- Account expiry (see plans/account-expiry)
--
-- SQL is the only clock: input parsing, offset-to-UTC conversion, relative
-- deadlines, and the must-be-in-the-future check all happen here. Python only
-- ferries strings (db.set_user_expiry raises InvalidExpiryError on NULL).
-- ============================================================================

-- Normalize an admin-supplied timestamp to the canonical millisecond-+00:00
-- form, or NULL when it is unparseable or not in the future. strftime accepts
-- the ISO-8601 time-string subset (bare date, ...THH:MM[:SS], optional Z or
-- ±HH:MM offset — converted to UTC) and returns NULL for anything else, so one
-- query does validation + normalization in a single place.
-- name: normalizeFutureTimestamp :value
SELECT CASE
    WHEN strftime('%Y-%m-%dT%H:%M:%f', $value::text) || '+00:00'
         > strftime('%Y-%m-%dT%H:%M:%f', 'now') || '+00:00'
    THEN strftime('%Y-%m-%dT%H:%M:%f', $value::text) || '+00:00'
END;

-- The relative form: a deadline `days` from now (same printf-modifier
-- convention as setLockedUntil / insertSession). Positivity is validated in
-- Python — the one check that isn't a datetime operation.
-- name: expiryInDays :value
SELECT strftime('%Y-%m-%dT%H:%M:%f', 'now', printf('%+d days', $days::integer))
       || '+00:00';

-- NULL clears; a non-NULL value has already been normalized by
-- normalizeFutureTimestamp / expiryInDays inside the same transaction.
-- name: setUserExpiry
UPDATE datasette_accounts_users
SET expires_at = $expires_at::text::,
    updated_at = strftime('%Y-%m-%dT%H:%M:%f', 'now') || '+00:00'
WHERE id = $user_id::text;

-- ============================================================================
-- Sessions
-- ============================================================================

-- name: selectSession :row -> SessionRow
SELECT token_sha256, actor_id, created_at, expires_at, last_seen_at, user_agent, ip
FROM datasette_accounts_sessions
WHERE token_sha256 = $token_sha256::text;

-- name: listSessionsForUser :rows -> SessionRow
SELECT token_sha256, actor_id, created_at, expires_at, last_seen_at, user_agent, ip
FROM datasette_accounts_sessions
WHERE actor_id = $actor_id::text
ORDER BY last_seen_at DESC;

-- Create a session that expires `ttl_days` from now.
-- name: insertSession
INSERT INTO datasette_accounts_sessions
    (token_sha256, actor_id, created_at, expires_at, last_seen_at, user_agent, ip)
VALUES ($token_sha256::text, $actor_id::text,
        strftime('%Y-%m-%dT%H:%M:%f', 'now') || '+00:00',
        strftime('%Y-%m-%dT%H:%M:%f', 'now', printf('%+d days', $ttl_days::integer))
        || '+00:00',
        strftime('%Y-%m-%dT%H:%M:%f', 'now') || '+00:00',
        $user_agent::text::, $ip::text::);

-- name: touchLastSeen
UPDATE datasette_accounts_sessions
SET last_seen_at = strftime('%Y-%m-%dT%H:%M:%f', 'now') || '+00:00'
WHERE token_sha256 = $token_sha256::text;

-- name: deleteSession
DELETE FROM datasette_accounts_sessions WHERE token_sha256 = $token_sha256::text;

-- name: deleteSessionForActor
DELETE FROM datasette_accounts_sessions
WHERE token_sha256 = $token_sha256::text AND actor_id = $actor_id::text;

-- name: deleteSessionsForActor
DELETE FROM datasette_accounts_sessions WHERE actor_id = $actor_id::text;

-- Delete all of an actor's sessions except the current one (change-own-password).
-- name: deleteOtherSessionsForActor
DELETE FROM datasette_accounts_sessions
WHERE actor_id = $actor_id::text AND token_sha256 != $token_sha256::text;

-- name: deleteExpiredSessions
DELETE FROM datasette_accounts_sessions
WHERE expires_at <= strftime('%Y-%m-%dT%H:%M:%f', 'now') || '+00:00';

-- ============================================================================
-- Login audit
-- ============================================================================

-- name: insertLoginAttempt
INSERT INTO datasette_accounts_login_audit (username, ip, timestamp, success, reason)
VALUES ($username::text::, $ip::text::,
        strftime('%Y-%m-%dT%H:%M:%f', 'now') || '+00:00',
        $success::integer, $reason::text::);

-- Most-recent-first login-audit rows with optional exact username/ip filters
-- (AND-combined). A NULL filter param disables that clause, collapsing the old
-- dynamic WHERE builder into one static query. `limit` is clamped in db.py.
-- name: listLoginAttempts :rows -> LoginAttemptRow
SELECT id, username, ip, timestamp, success, reason
FROM datasette_accounts_login_audit
WHERE ($username::text:: IS NULL OR username = $username::text::)
  AND ($ip::text:: IS NULL OR ip = $ip::text::)
ORDER BY id DESC
LIMIT $limit::integer;

-- Purge audit rows older than `retention_days`.
-- name: purgeLoginAudit
DELETE FROM datasette_accounts_login_audit
WHERE timestamp <
    strftime('%Y-%m-%dT%H:%M:%f', 'now', printf('-%d days', $retention_days::integer))
    || '+00:00';

-- ============================================================================
-- Admin audit
-- ============================================================================

-- name: insertAdminAudit
INSERT INTO datasette_accounts_admin_audit
    (timestamp, operation, actor_id, target_id, detail)
VALUES (strftime('%Y-%m-%dT%H:%M:%f', 'now') || '+00:00',
        $operation::text, $actor_id::text::, $target_id::text::, $detail::text::);

-- ============================================================================
-- Capability grants
-- ============================================================================

-- Insert a capability grant, ignoring duplicates (partial unique indexes).
-- RETURNING id yields a row only when a row was actually inserted, so the
-- helper returns the new id on insert and None when the grant already existed.
-- name: insertCapabilityGrant :value
INSERT OR IGNORE INTO datasette_accounts_capability_grants
    (action, principal_type, actor_id, group_id, created_at, created_by)
VALUES ($action::text, $principal_type::text, $actor_id::text::, $group_id::integer::,
        strftime('%Y-%m-%dT%H:%M:%f', 'now') || '+00:00', $created_by::text::)
RETURNING id;

-- Row backing revoke-capability's audit detail; None when the id is unknown.
-- name: selectCapabilityGrant :row -> CapabilityGrantRow
SELECT action, principal_type, actor_id, group_id
FROM datasette_accounts_capability_grants
WHERE id = $grant_id::integer;

-- name: deleteCapabilityGrant
DELETE FROM datasette_accounts_capability_grants WHERE id = $grant_id::integer;

-- ============================================================================
-- Site messages
-- ============================================================================

-- name: listSiteMessages :rows -> SiteMessageRow
SELECT key, body FROM datasette_accounts_site_messages;

-- name: selectSiteMessage :value
SELECT body FROM datasette_accounts_site_messages WHERE key = $key::text;

-- name: upsertSiteMessage
INSERT INTO datasette_accounts_site_messages (key, body, updated_at, updated_by)
VALUES ($key::text, $body::text,
        strftime('%Y-%m-%dT%H:%M:%f', 'now') || '+00:00', $updated_by::text::)
ON CONFLICT(key) DO UPDATE SET
    body = excluded.body, updated_at = excluded.updated_at,
    updated_by = excluded.updated_by;

-- Delete a site-message slot; RETURNING key is non-empty only when a row
-- existed, so the helper reports whether anything was cleared.
-- name: deleteSiteMessage :value
DELETE FROM datasette_accounts_site_messages WHERE key = $key::text RETURNING key;

-- ============================================================================
-- Password tokens (one-time invite / reset links — see plans/invite-links)
-- ============================================================================

-- Insert a fresh token with SQL-side created_at = now, expires_at = now +
-- ttl_hours.
-- name: insertPasswordToken
INSERT INTO datasette_accounts_password_tokens
    (token_sha256, user_id, purpose, created_at, expires_at, created_by)
VALUES ($token_sha256::text, $user_id::text, $purpose::text,
        strftime('%Y-%m-%dT%H:%M:%f', 'now') || '+00:00',
        strftime('%Y-%m-%dT%H:%M:%f', 'now', printf('%+d hours', $ttl_hours::integer))
        || '+00:00',
        $created_by::text::);

-- Look up a live (non-expired) token for the GET set-password page, joining
-- the target username for display.
-- name: selectPasswordToken :row -> PasswordTokenRow
SELECT t.token_sha256, t.user_id, t.purpose, t.created_at, t.expires_at,
       t.created_by, u.username
FROM datasette_accounts_password_tokens t
JOIN datasette_accounts_users u ON u.id = t.user_id
WHERE t.token_sha256 = $token_sha256::text
  AND t.expires_at > strftime('%Y-%m-%dT%H:%M:%f', 'now') || '+00:00';

-- Claim-by-delete: single-use, and the expiry check lives in the DELETE
-- itself so an expired-but-unpurged row can never be claimed (a double-submit
-- race and an expired claim both just find no row). RETURNING user_id is
-- non-empty only when a live token was actually deleted.
-- name: deletePasswordToken :value
DELETE FROM datasette_accounts_password_tokens
WHERE token_sha256 = $token_sha256::text
  AND expires_at > strftime('%Y-%m-%dT%H:%M:%f', 'now') || '+00:00'
RETURNING user_id;

-- Used when minting (one live link per account) and by disable/delete/reset.
-- name: deletePasswordTokensForUser
DELETE FROM datasette_accounts_password_tokens WHERE user_id = $user_id::text;

-- Housekeeping — called alongside deleteExpiredSessions.
-- name: purgeExpiredPasswordTokens
DELETE FROM datasette_accounts_password_tokens
WHERE expires_at <= strftime('%Y-%m-%dT%H:%M:%f', 'now') || '+00:00';

-- User ids holding a live (unexpired) invite token. Merged into the admin
-- user rows as the `invited` flag — deliberately not a users column (see
-- plans/invite-links: the live token *is* the invited state).
-- name: listInvitedUserIds :list
SELECT user_id FROM datasette_accounts_password_tokens
WHERE purpose = 'invite'
  AND expires_at > strftime('%Y-%m-%dT%H:%M:%f', 'now') || '+00:00';

-- Completing a token: set the password, clear must_change_password (the link
-- itself proved control), stamp updated_at.
-- name: setPasswordFromToken
UPDATE datasette_accounts_users
SET password_hash = $password_hash::text, must_change_password = 0,
    updated_at = strftime('%Y-%m-%dT%H:%M:%f', 'now') || '+00:00'
WHERE id = $user_id::text;
