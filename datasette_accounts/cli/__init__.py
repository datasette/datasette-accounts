"""The ``datasette accounts`` command group.

``base`` defines the group + shared helpers; each sibling module defines one
subcommand and registers it on the group at import time. Importing them here (for
their registration side effects) is what assembles the full command surface, so
``from datasette_accounts.cli import accounts`` yields the complete group.
"""

from .base import accounts

# Import each command module for its registration side effect. Order is
# irrelevant — AccountsGroup.format_commands sorts the help into fixed sections.
from . import (  # noqa: E402,F401
    approve,
    audit,
    bootstrap_admin,
    create,
    delete,
    demote,
    disable,
    enable,
    expire,
    hash_password,
    invite,
    list_accounts,
    login_attempts,
    logout,
    promote,
    registration,
    reject,
    reset_link,
    reset_password,
    unlock,
)

__all__ = ["accounts"]
