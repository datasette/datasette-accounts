"""Registry conformance: everything emitted is registered, everything
registered is emitted, and no signal names a person or carries a secret.

One broad workload through a real Datasette (password + demo provider), then a
single ``collect()`` — the kit's reader uses delta temporality, so an earlier
collect would drain the measurements — then the kit's helpers.
"""

import json
from urllib.parse import parse_qs, urlparse

import pytest
from datasette.telemetry_testing import (
    assert_metrics_conform,
    assert_metrics_covered,
    assert_no_forbidden_values,
    assert_spans_conform,
    assert_spans_covered,
)
from providers_util import JSON, insert_user, make_ds, session_cookie

from datasette_accounts import db
from datasette_accounts import telemetry_registry as r
from datasette_accounts.providers import STATE_COOKIE, get_registry
from datasette_accounts.security import COOKIE_NAME, SIGN_NAMESPACE
from datasette_accounts.sessions import token_sha256

SCOPE = "datasette_accounts"

# Sentinels planted in the workload: none may appear in any signal, from our
# scope or core's.
USERNAMES = ("sentinel-ana", "sentinel-bo", "sentinel-cy", "sentinel-newbie")
SUBJECT = "sentinel-subject-7f3a"
PIN = "9173"


async def _workload(ds):
    internal = ds.get_internal_database()
    forbidden = set(USERNAMES) | {SUBJECT}

    async def login(username, password="password123"):
        return await ds.client.post(
            "/-/login/api/authenticate",
            content=json.dumps({"username": username, "password": password}),
            headers=JSON,
        )

    ana = await insert_user(ds, "sentinel-ana")
    bo = await insert_user(ds, "sentinel-bo")
    cy = await insert_user(ds, "sentinel-cy", must_change_password=True)
    forbidden |= {ana, bo, cy}

    # An expired session for login-time housekeeping to purge.
    stale = await session_cookie(ds, bo)
    await internal.execute_write(
        f"UPDATE {db.SESSIONS} SET expires_at = '2000-01-01T00:00:00.000+00:00'"
    )

    # Anonymous + garbage-cookie traffic.
    await ds.client.get("/")
    await ds.client.get("/", cookies={COOKIE_NAME: "garbage"})

    # Password: ok (mints, housekeeping purges the stale session), then use it.
    ok = await login("sentinel-ana")
    assert ok.status_code == 200
    session = ok.cookies.get(COOKIE_NAME)
    await ds.client.get("/", cookies={COOKIE_NAME: session})

    # Password refusals: unknown user, bad password to lockout, then locked.
    await login("sentinel-nobody")
    forbidden.add("sentinel-nobody")
    for _ in range(2):
        assert (await login("sentinel-bo", "wrong-password")).status_code == 401
    assert (await login("sentinel-bo")).status_code == 429

    # Forced password change bounce.
    cy_cookie = await session_cookie(ds, cy)
    await ds.client.get("/-/versions", cookies={COOKIE_NAME: cy_cookie})

    # Self-registration (password provider, approval).
    await db.set_registration_enabled(internal, "root", True)
    registered = await ds.client.post(
        "/-/register/api/submit",
        content=json.dumps({"username": "sentinel-newbie", "password": "pw-123456"}),
        headers=JSON,
    )
    assert registered.status_code == 200

    # Demo provider, auto sign-ups: start -> callback provisions + mints.
    installed = list(get_registry(ds))
    await db.set_provider_enabled(
        internal, "root", "demo", True, installed_keys=installed
    )
    await db.set_provider_signups(internal, "root", "demo", "auto")
    start = await ds.client.get("/-/demo-auth/start")
    state = parse_qs(urlparse(start.headers["location"]).query)["state"][0]
    state_cookie = start.cookies.get(STATE_COOKIE)
    forbidden |= {state, state_cookie}
    callback = await ds.client.get(
        f"/-/demo-auth/callback?state={state}&subject={SUBJECT}&pin={PIN}",
        cookies={STATE_COOKIE: state_cookie},
    )
    assert callback.status_code == 302
    # A state failure (no cookie).
    await ds.client.get(f"/-/demo-auth/callback?state={state}&subject=x&pin=1234")

    for cookie in (session, stale, cy_cookie, callback.cookies.get(COOKIE_NAME)):
        forbidden |= {cookie, token_sha256(ds.unsign(cookie, SIGN_NAMESPACE))}
    return forbidden


@pytest.mark.asyncio
async def test_registry_conformance(otel_spans, otel_metrics):
    ds = await make_ds(lockout_threshold=2)
    forbidden = await _workload(ds)
    finished = otel_spans.get_finished_spans()
    otel_metrics.collect()

    assert_spans_conform(r.SPANS, finished, scope_name=SCOPE)
    assert_spans_covered(r.SPANS, finished, scope_name=SCOPE)
    assert_metrics_conform(r.METRICS, otel_metrics, scope_name=SCOPE)
    assert_metrics_covered(r.METRICS, otel_metrics, scope_name=SCOPE)
    # Every scope, not just ours: a leak through core's signals is still a leak.
    assert_no_forbidden_values(
        sorted(f for f in forbidden if f),
        finished_spans=finished,
        collector=otel_metrics,
    )
