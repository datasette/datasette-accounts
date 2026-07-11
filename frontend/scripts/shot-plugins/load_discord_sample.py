"""Shim that loads the real Discord sample provider into the screenshots harness.

``just dev`` loads ``samples/discord-auth`` via ``--plugins-dir``. The shots
harness already spends its single ``--plugins-dir`` on this ``shot-plugins``
directory (Datasette takes only one — a second flag overrides the first), so this
loose file imports the sample from its canonical path and re-exports its
``datasette_accounts_auth_providers`` hookimpl. That way the login shot shows the
real "Continue with Discord" button and the Configuration shot shows a real
external-provider row, driven by the exact code shipped in ``samples/`` (no
duplication). seed.py enables the discord provider; the sample module needs no
Discord credentials to register (only ``start`` requires them).
"""

import importlib.util
from pathlib import Path

from datasette import hookimpl

_SAMPLE = (
    Path(__file__).resolve().parents[3] / "samples" / "discord-auth" / "discord_auth.py"
)
# Name the module "discord_auth" so the Configuration shot's provider Source
# column reads exactly as it does under `just dev` (which loads the file by that
# basename), rather than a shim-specific alias.
_spec = importlib.util.spec_from_file_location("discord_auth", _SAMPLE)
_module = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_module)


@hookimpl
def datasette_accounts_auth_providers(datasette):
    return _module.datasette_accounts_auth_providers(datasette)
