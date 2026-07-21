"""The built-in username/password provider.

Core-01 ships only the **descriptor**: it reserves the ``password`` key and
holds the first, always-present slot in the registry (design §3/§8). The flow
code — today's ``authenticate`` / register / set-password completion, refactored
to terminate at ``finish_login`` — moves into this module in core-02. The
canonical URLs (``/-/login``, ``/-/register``, ``/-/set-password``) do not change
when it does.
"""

from . import AuthProvider


class PasswordProvider(AuthProvider):
    key = "password"
    label = "Username & password"
    # The canonical login page — where the login button points; the real routes
    # already exist under routes/api.py + routes/pages.py (unchanged in core-01).
    start_path = "/-/login"
