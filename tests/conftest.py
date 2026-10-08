import types

import pytest

# Datasette's plugin telemetry kit: a session-wide in-memory SDK provider
# (spans + delta-temporality metrics), drained after every test.
from datasette.telemetry_testing import (  # noqa: F401
    install_metric_reader,
    install_span_exporter,
    otel_meter_provider,
    otel_metrics,
    otel_provider,
    otel_reset,
    otel_spans,
)

# Install the kit's providers BEFORE datasette.plugins loads entry points:
# the dev-group datasette-otel-viewer installs its own global tracer/meter
# providers when imported, and OpenTelemetry allows one per process — if it
# won, every telemetry test would skip. It then defers to ours, and is
# unregistered so its startup hook (which creates ./otel.db) never runs here.
install_span_exporter()
install_metric_reader()

from datasette import hookimpl  # noqa: E402
from datasette.plugins import pm  # noqa: E402

if pm.get_plugin("otel_viewer") is not None:
    pm.unregister(name="otel_viewer")

from datasette_accounts.providers import provider_gate  # noqa: E402

# Run first: it forks a fresh interpreter, which can SIGBUS on macOS once the
# process holds many threads (the kit's documented caveat).
_FRONT_LOADED = ("test_package_never_imports_the_sdk",)


def pytest_collection_modifyitems(items):
    items.sort(key=lambda item: item.name not in _FRONT_LOADED)


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


@pytest.fixture
def register_providers(register_provider):
    """``register_provider`` for several descriptors at once (one module)."""

    def _register(providers):
        for provider in providers:
            register_provider(provider)

    return _register
