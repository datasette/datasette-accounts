"""``datasette accounts unlock`` — clear a user's lockout counters."""

from .base import _simple_mutation

unlock = _simple_mutation(
    "unlock",
    "unlock_user",
    "Clear a user's lockout counters.",
    "Unlocked",
    lambda u: f"Clear the lockout for {u!r}?",
)
