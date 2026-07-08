"""``datasette accounts logout`` — revoke all of a user's sessions."""

from .base import _simple_mutation

logout = _simple_mutation(
    "logout",
    "logout_everywhere",
    "Revoke all of a user's sessions.",
    "Logged out",
    lambda u: f"Revoke all sessions for {u!r}?",
)
