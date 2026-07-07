"""``datasette accounts disable`` — disable a user + revoke their sessions."""

from .base import _simple_mutation

disable = _simple_mutation(
    "disable",
    "disable_user",
    "Disable a user + revoke their sessions.",
    "Disabled",
    lambda u: f"Disable {u!r} and revoke their sessions?",
)
