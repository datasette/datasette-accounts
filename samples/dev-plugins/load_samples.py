"""Loader that serves every sample provider through one ``--plugins-dir``.

Datasette accepts a single ``--plugins-dir`` (a second flag overrides the
first), so ``just dev`` points here and this loose module imports each sibling
sample (``samples/*-auth/*.py``) and re-exports their hookimpls, aggregated.
Only the hooks relayed below reach Datasette — pluggy never sees the sample
modules themselves — so a sample needing another hook must have it added here.
Each sample module is imported under its own basename ("discord_auth",
"github_auth", …) so the admin Configuration table's provider Source column
reads the same as when a sample is loaded directly via its own directory.

The screenshots harness re-exports this same loader (see
``frontend/scripts/shot-plugins/load_sample_providers.py``). Adding a new
sample directory requires no change to either file.
"""

import importlib.util
from pathlib import Path

from datasette import hookimpl
from datasette.utils import await_me_maybe

_SAMPLES = Path(__file__).resolve().parents[1]


def _load_sample_modules():
    modules = []
    for sample_dir in sorted(_SAMPLES.glob("*-auth")):
        for py in sorted(sample_dir.glob("*.py")):
            spec = importlib.util.spec_from_file_location(py.stem, py)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            modules.append(module)
    return modules


_modules = _load_sample_modules()


@hookimpl
def datasette_accounts_auth_providers(datasette):
    providers = []
    for module in _modules:
        providers.extend(module.datasette_accounts_auth_providers(datasette))
    return providers


@hookimpl
def register_routes():
    routes = []
    for module in _modules:
        routes.extend(module.register_routes())
    return routes


@hookimpl
def startup(datasette):
    # Samples that own tables in the internal DB create them in their startup
    # hookimpl (e.g. bluesky-auth's flow table). Datasette runs each startup
    # result through await_me_maybe, so relay with the same semantics.
    results = [
        module.startup(datasette) for module in _modules if hasattr(module, "startup")
    ]

    async def inner():
        for result in results:
            await await_me_maybe(result)

    return inner
