"""``datasette accounts promote`` — grant admin to a user."""

from .base import _set_admin_command

promote = _set_admin_command(
    "promote",
    True,
    "Grant admin to a user (explicit is_admin=1).",
    lambda u: f"Grant admin to {u!r}?",
)
