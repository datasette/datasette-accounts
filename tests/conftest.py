import types

import pytest
from datasette import hookimpl
from datasette.plugins import pm

from datasette_accounts.providers import provider_gate


@pytest.fixture
def register_provider():
    """Register a throwaway sign-in provider the way an installed package would:
    the ``datasette_accounts_auth_providers`` hook publishes the descriptor and
    ``register_routes`` mounts its own routes under ``/-/{key}-auth/...``, each
    wrapped in ``provider_gate``.

    A test provider lists its route names in ``paths`` and implements each as
    an ``async def name(self, datasette, request)`` method. Registration must
    happen before ``make_ds()`` (the registry is built at startup); every
    registered module is unregistered on teardown."""
    names = []

    def _register(provider, name=None):
        name = name or f"test-provider-{len(names)}"
        mod = types.ModuleType(name)
        gate = provider_gate(provider.key)
        routes = [
            (rf"/-/{provider.key}-auth/{path}$", gate(getattr(provider, path)))
            for path in getattr(provider, "paths", ())
        ]

        @hookimpl
        def datasette_accounts_auth_providers(datasette):
            return [provider]

        @hookimpl
        def register_routes():
            return routes

        mod.datasette_accounts_auth_providers = datasette_accounts_auth_providers
        mod.register_routes = register_routes
        pm.register(mod, name=name)
        names.append(name)
        return provider

    yield _register
    for name in names:
        if pm.get_plugin(name) is not None:
            pm.unregister(name=name)
