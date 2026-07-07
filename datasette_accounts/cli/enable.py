"""``datasette accounts enable`` — re-enable a user."""

from .base import _simple_mutation

enable = _simple_mutation(
    "enable",
    "enable_user",
    "Re-enable a user.",
    "Enabled",
    lambda u: f"Enable {u!r}?",
)
