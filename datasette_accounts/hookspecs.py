"""Hookspec published by datasette-accounts for sign-in provider plugins."""

from pluggy import HookspecMarker

hookspec = HookspecMarker("datasette")


@hookspec
def datasette_accounts_auth_providers(datasette):
    """Return a list of AuthProvider instances (or an awaitable of one)."""
