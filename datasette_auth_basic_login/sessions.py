"""Session token helpers.

The raw token lives only in the user's (signed) cookie. The table stores only
``sha256(raw_token)`` so a DB read leak cannot resurrect a live session.
"""

import hashlib
import secrets


def mint_token() -> str:
    """A fresh opaque session token (goes in the cookie, signed)."""
    return secrets.token_urlsafe(32)


def token_sha256(raw_token: str) -> str:
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
