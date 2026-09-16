"""The built-in username/password provider.

The descriptor reserves the ``password`` key and holds the first, always-present
slot in the registry (design §3/§8). Its ``start_path`` is the canonical
``/-/login`` page: the built-in provider owns the real, documented password
surface (``/-/login`` / ``/-/register`` / ``/-/set-password`` and their APIs in
``routes/``), so it needs no separate start route.
"""

from . import AuthProvider


class PasswordProvider(AuthProvider):
    key = "password"
    label = "Username & password"
    # The login-page code never renders a button for the password provider (it
    # renders the form), so start_path is only a truthful descriptor value.
    start_path = "/-/login"
