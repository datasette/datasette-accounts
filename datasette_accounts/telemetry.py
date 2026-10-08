"""OpenTelemetry tracer, meter and instruments for datasette-accounts.

Emits through ``opentelemetry-api`` only: with no SDK provider installed every
call here is a no-op. Operators turn it on the same way as for Datasette core
(``opentelemetry-instrument datasette ...`` or an embedding app's provider).
Names, descriptions and enum values live in ``telemetry_registry``.
"""

import contextlib
import time
from importlib.metadata import PackageNotFoundError, version

from datasette.telemetry import SCHEMA_URL
from opentelemetry import metrics as otel_metrics
from opentelemetry import trace as otel_trace

from . import telemetry_registry as r

try:
    _VERSION = version("datasette-accounts")
except PackageNotFoundError:  # pragma: no cover - running from a bare checkout
    _VERSION = None

SCOPE = "datasette_accounts"

tracer = otel_trace.get_tracer(SCOPE, _VERSION, schema_url=SCHEMA_URL)
meter = otel_metrics.get_meter(SCOPE, _VERSION, schema_url=SCHEMA_URL)


def _counter(name):
    return meter.create_counter(name, unit=name.unit, description=name.description)


def _histogram(name):
    return meter.create_histogram(
        name,
        unit=name.unit,
        description=name.description,
        explicit_bucket_boundaries_advisory=list(name.buckets),
    )


actor_resolutions = _counter(r.M_ACTOR_RESOLUTIONS)
actor_resolve_duration = _histogram(r.M_ACTOR_RESOLVE_DURATION)
forced_change_blocked = _counter(r.M_FORCED_CHANGE_BLOCKED)
logins = _counter(r.M_LOGINS)
login_duration = _histogram(r.M_LOGIN_DURATION)
password_verifications = _counter(r.M_PASSWORD_VERIFICATIONS)
lockouts = _counter(r.M_LOCKOUTS)
kdf_duration = _histogram(r.M_KDF_DURATION)
registrations = _counter(r.M_REGISTRATIONS)
state_reads = _counter(r.M_STATE_READS)
rows_purged = _counter(r.M_ROWS_PURGED)


def set_current_attribute(key, value):
    """Set ``key`` on the current span if one is recording (a no-op otherwise)."""
    span = otel_trace.get_current_span()
    if span.is_recording():
        span.set_attribute(key, value)


@contextlib.contextmanager
def record_duration(histogram, attributes):
    """Record the wrapped block's wall time on ``histogram`` in seconds, even
    when it raises. Recorded inside any open span so the SDK can attach a
    trace exemplar."""
    started = time.perf_counter()
    try:
        yield
    finally:
        histogram.record(time.perf_counter() - started, attributes)


def record_registration(provider, outcome, reason=None):
    attributes = {r.PROVIDER: provider, r.LOGIN_OUTCOME: outcome}
    if reason is not None:
        attributes[r.REGISTRATION_REASON] = reason
    registrations.add(1, attributes)
