"""Retention housekeeping, run at startup and after every successful login."""

from . import db, security, telemetry
from . import telemetry_registry as r


async def housekeeping(datasette, *, trigger):
    """Purge expired sessions, expired password tokens and old audit rows.

    ``trigger`` is ``"startup"`` or ``"login"``; it only labels the telemetry.
    """
    internal = datasette.get_internal_database()
    with telemetry.tracer.start_as_current_span(
        r.S_HOUSEKEEPING, attributes={r.TRIGGER: trigger}
    ) as span:
        purged = {
            "sessions": await db.delete_expired_sessions(internal),
            "password_tokens": await db.purge_expired_password_tokens(internal),
            "login_audit": await db.purge_login_audit(
                internal, security.config(datasette, "audit_retention_days")
            ),
            "admin_audit": await db.purge_admin_audit(
                internal, security.config(datasette, "admin_audit_retention_days")
            ),
        }
        span.set_attributes(
            {
                r.PURGED_SESSIONS: purged["sessions"],
                r.PURGED_PASSWORD_TOKENS: purged["password_tokens"],
                r.PURGED_LOGIN_AUDIT: purged["login_audit"],
                r.PURGED_ADMIN_AUDIT: purged["admin_audit"],
            }
        )
    for table, count in purged.items():
        if count:
            telemetry.rows_purged.add(count, {r.PURGE_TABLE: table, r.TRIGGER: trigger})
