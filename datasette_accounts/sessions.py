"""Session token helpers.

The raw token lives only in the user's (signed) cookie. The table stores only
``sha256(raw_token)`` so a DB read leak cannot resurrect a live session.
"""

import hashlib
import secrets

from . import db
from .page_data import OwnSessionRow, SessionRow
from .security import COOKIE_NAME, SIGN_NAMESPACE


def mint_token() -> str:
    """A fresh opaque session token (goes in the cookie, signed)."""
    return secrets.token_urlsafe(32)


def token_sha256(raw_token: str) -> str:
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


def current_token_sha(datasette, request):
    """The requesting cookie's session, hashed — or None if absent/invalid.

    Shared by ``routes/api.py`` (logout, change-password) and
    ``routes/pages.py`` (stamping the account page's own-sessions list) so both
    unsign the session cookie the same way.
    """
    cookie = request.cookies.get(COOKIE_NAME)
    if not cookie:
        return None
    try:
        raw = datasette.unsign(cookie, SIGN_NAMESPACE)
    except Exception:
        return None
    return token_sha256(raw)


async def list_own_sessions(datasette, request, internal, actor_id):
    """The caller's own sessions, most-recently-active first, current stamped.

    Shared by ``routes/pages.py`` (the account page's initial render) and
    ``routes/api.py`` (the in-page refresh endpoint) so the two "my sessions"
    assembly paths can't drift apart.
    """
    rows = await db.list_sessions_for_user(internal, actor_id)
    current = current_token_sha(datasette, request)
    sessions = [
        OwnSessionRow(
            **{k: r.get(k) for k in SessionRow.model_fields},
            current=(r["token_sha256"] == current),
        )
        for r in rows
    ]
    sessions.sort(key=lambda s: s.last_seen_at, reverse=True)
    return sessions
