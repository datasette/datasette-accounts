"""Shim that loads the real sample providers into the screenshots harness.

``just dev`` loads every sample via ``samples/dev-plugins`` and its single
``--plugins-dir``. The shots harness already spends its own single
``--plugins-dir`` on this ``shot-plugins`` directory (Datasette takes only one —
a second flag overrides the first), so this loose file imports that same
dev-plugins loader by path and re-exports its aggregated hookimpls. That way the
login shot shows the real "Continue with Discord" / "Continue with GitHub"
buttons and the Configuration shot shows real external-provider rows, driven by
the exact code shipped in ``samples/`` (no duplication). seed.py enables both
providers; the sample modules need no real credentials to register (only their
``start`` routes require them, and screenshots.mjs injects fakes so
``configured()`` reports True).
"""

import importlib.util
from pathlib import Path

from datasette import hookimpl

_LOADER = (
    Path(__file__).resolve().parents[3] / "samples" / "dev-plugins" / "load_samples.py"
)
_spec = importlib.util.spec_from_file_location("load_samples", _LOADER)
_module = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_module)


@hookimpl
def datasette_accounts_auth_providers(datasette):
    return _module.datasette_accounts_auth_providers(datasette)


@hookimpl
def register_routes():
    # The samples own their routes (design D3b) — re-export them so the shots
    # harness serves /-/discord-auth/... and /-/github-auth/... exactly as
    # `just dev` does, driven by the same sample code.
    return _module.register_routes()
