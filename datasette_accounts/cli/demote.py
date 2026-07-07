"""``datasette accounts demote`` — remove admin from a user."""

from .base import _set_admin_command

demote = _set_admin_command(
    "demote",
    False,
    "Remove admin from a user (last-admin guarded).",
    lambda u: f"Remove admin from {u!r}?",
)
