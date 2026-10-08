"""Targeted tests for the OpenTelemetry spans + metrics (``telemetry.py``).

The registry-wide conformance + privacy checks live in
``test_telemetry_registry.py``; this file pins individual behaviours. Spans
and metrics come from the kit's in-memory fixtures (``conftest.py``).
"""

import ast
import json
import pathlib
from importlib.metadata import version
from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qs, urlparse

import pytest
from datasette.telemetry_testing import assert_package_never_imports_sdk
from providers_util import JSON, enable_provider, insert_user, make_ds, session_cookie

import datasette_accounts
from datasette_accounts import db
from datasette_accounts import telemetry_registry as r
from datasette_accounts.housekeeping import housekeeping
from datasette_accounts.providers import STATE_COOKIE, STATE_NAMESPACE
from datasette_accounts.security import COOKIE_NAME, SIGN_NAMESPACE

SCOPE = "datasette_accounts"


def ours(exporter, name=None):
    spans = [
        s
        for s in exporter.get_finished_spans()
        if s.instrumentation_scope and s.instrumentation_scope.name == SCOPE
    ]
    if name is not None:
        spans = [s for s in spans if s.name == name]
    return spans


def only(exporter, name):
    spans = ours(exporter, name)
    assert len(spans) == 1, [s.name for s in ours(exporter)]
    return spans[0]


def total(collector, name, attributes=None):
    return sum(p.value for p in collector.points(name, attributes))


async def login(ds, username, password="password123"):
    return await ds.client.post(
        "/-/login/api/authenticate",
        content=json.dumps({"username": username, "password": password}),
        headers=JSON,
    )


# --------------------------------------------------------------------------
# Scaffold
# --------------------------------------------------------------------------


def test_package_never_imports_the_sdk(monkeypatch):
    # The check imports us in a fresh interpreter, where datasette would load
    # every installed plugin — including the dev-group datasette-otel-viewer,
    # which does import the SDK. An empty allowlist loads none, so this tests
    # our package alone.
    monkeypatch.setenv("DATASETTE_LOAD_PLUGINS", "")
    assert_package_never_imports_sdk("datasette_accounts")


def test_tracer_scope_and_schema(otel_spans):
    from datasette.telemetry import SCHEMA_URL

    from datasette_accounts import telemetry

    with telemetry.tracer.start_as_current_span(r.S_REGISTRY_BUILD):
        pass
    (span,) = ours(otel_spans)
    scope = span.instrumentation_scope
    assert (scope.name, scope.schema_url) == ("datasette_accounts", SCHEMA_URL)
    assert scope.version == version("datasette-accounts")


@pytest.mark.asyncio
async def test_callbacks_are_named(otel_spans):
    """Every internal-DB callback reports a readable ``datasette.callback`` —
    no ``<lambda>`` (core names callback spans by ``__qualname__``)."""
    ds = await make_ds()
    await insert_user(ds, "alice")
    await enable_provider(ds, "demo")
    cookie = (await login(ds, "alice")).cookies.get(COOKIE_NAME)
    await ds.client.get("/", cookies={COOKIE_NAME: cookie})
    await login(ds, "alice", "wrong-password")
    await ds.client.get("/-/demo-auth/start")
    callbacks = [
        s.attributes.get("datasette.callback")
        for s in otel_spans.get_finished_spans()
        if s.name == "db.query"
    ]
    assert callbacks
    assert not [c for c in callbacks if c and "<lambda>" in c]


def _source_reasons():
    """Every refusal reason the source writes to login_audit: string constants
    in ``record_login_attempt``'s reason argument, assigned to a ``reason``
    variable, or returned by ``_gate_reason``."""
    found = set()
    root = pathlib.Path(datasette_accounts.__file__).parent
    for path in root.rglob("*.py"):
        if "_generated" in path.name:
            continue
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Call)
                and getattr(node.func, "attr", None) == "record_login_attempt"
            ):
                args = node.args[4:5] + [
                    k.value for k in node.keywords if k.arg == "reason"
                ]
                found |= {
                    c.value
                    for a in args
                    for c in ast.walk(a)
                    if isinstance(c, ast.Constant) and isinstance(c.value, str)
                }
            elif isinstance(node, ast.Assign) and any(
                getattr(t, "id", None) == "reason" for t in node.targets
            ):
                for c in ast.walk(node.value):
                    if isinstance(c, ast.Constant) and isinstance(c.value, str):
                        found.add(c.value)
            elif isinstance(node, ast.FunctionDef) and node.name == "_gate_reason":
                for ret in ast.walk(node):
                    if isinstance(ret, ast.Return) and ret.value is not None:
                        for c in ast.walk(ret.value):
                            if isinstance(c, ast.Constant) and isinstance(c.value, str):
                                found.add(c.value)
    return found - {"success", "reauth"}


def test_reason_vocabulary_matches_the_audit_source():
    assert set(r.AUDIT_REASONS) == _source_reasons()


# --------------------------------------------------------------------------
# resolve_actor + the forced-change gate
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_anonymous_request_counts_but_emits_no_span(otel_spans, otel_metrics):
    ds = await make_ds()
    otel_spans.clear()
    otel_metrics.collect()  # drain startup
    await ds.client.get("/")
    otel_metrics.collect()
    assert ours(otel_spans, r.S_RESOLVE_ACTOR) == []
    # Once per caller: the forced-change gate and core's actor hook.
    for caller in ("asgi_wrapper", "actor_from_request"):
        point = otel_metrics.point(
            r.M_ACTOR_RESOLUTIONS, {r.ACTOR_OUTCOME: "no_cookie", r.CALLER: caller}
        )
        assert point.value == 1


@pytest.mark.asyncio
async def test_signed_in_request_resolves_twice(otel_spans, otel_metrics):
    ds = await make_ds()
    uid = await insert_user(ds, "alice")
    cookie = await session_cookie(ds, uid)
    otel_spans.clear()
    await ds.client.get("/", cookies={COOKIE_NAME: cookie})
    spans = ours(otel_spans, r.S_RESOLVE_ACTOR)
    assert sorted(s.attributes[r.CALLER] for s in spans) == [
        "actor_from_request",
        "asgi_wrapper",
    ]
    assert {s.attributes[r.ACTOR_OUTCOME] for s in spans} == {"ok"}
    # The 60s throttle lets at most one last_seen write through.
    assert sum(bool(s.attributes[r.LAST_SEEN_TOUCHED]) for s in spans) <= 1
    otel_metrics.collect()
    assert otel_metrics.points(r.M_ACTOR_RESOLVE_DURATION, {r.ACTOR_OUTCOME: "ok"})


async def _expire_session(ds, uid):
    cookie = await session_cookie(ds, uid)
    await ds.get_internal_database().execute_write(
        f"UPDATE {db.SESSIONS} SET expires_at = '2000-01-01T00:00:00.000+00:00'"
    )
    return cookie


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "setup,outcome",
    [
        ("garbage", "bad_signature"),
        ("unknown", "no_session"),
        ("expired_session", "session_expired"),
        ("deleted_user", "no_user"),
        ("disabled", "disabled"),
        ("user_expired", "user_expired"),
        ("pending", "pending"),
    ],
)
async def test_resolve_actor_outcomes(otel_spans, setup, outcome):
    ds = await make_ds()
    internal = ds.get_internal_database()
    kwargs = {
        "disabled": {"disabled": True},
        "user_expired": {"expires_at": "2000-01-01T00:00:00.000+00:00"},
        "pending": {"pending": True},
    }.get(setup, {})
    uid = await insert_user(ds, "alice", **kwargs)
    if setup == "garbage":
        cookie = "not-a-signed-value"
    elif setup == "unknown":
        cookie = ds.sign("no-such-token", SIGN_NAMESPACE)
    elif setup == "expired_session":
        cookie = await _expire_session(ds, uid)
    else:
        cookie = await session_cookie(ds, uid)
        if setup == "deleted_user":
            await internal.execute_write(f"DELETE FROM {db.USERS}")
    otel_spans.clear()
    await ds.client.get("/", cookies={COOKIE_NAME: cookie})
    outcomes = {
        s.attributes[r.ACTOR_OUTCOME] for s in ours(otel_spans, r.S_RESOLVE_ACTOR)
    }
    if setup == "expired_session":
        # The first resolve deletes the expired row; the second finds nothing.
        assert outcomes == {"session_expired", "no_session"}
    else:
        assert outcomes == {outcome}


@pytest.mark.asyncio
async def test_forced_change_gate_counts_both_response_modes(otel_metrics):
    ds = await make_ds()
    uid = await insert_user(ds, "alice", must_change_password=True)
    cookies = {COOKIE_NAME: await session_cookie(ds, uid)}
    otel_metrics.collect()
    html = await ds.client.get("/-/versions", cookies=cookies)
    api = await ds.client.get(
        "/-/versions.json", cookies=cookies, headers={"accept": "application/json"}
    )
    assert (html.status_code, api.status_code) == (302, 403)
    otel_metrics.collect()
    for mode in ("redirect", "json"):
        assert (
            otel_metrics.point(r.M_FORCED_CHANGE_BLOCKED, {r.RESPONSE_MODE: mode}).value
            == 1
        )


# --------------------------------------------------------------------------
# The login funnel
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_password_login_span_tree(otel_spans, otel_metrics):
    ds = await make_ds()
    await insert_user(ds, "alice")
    otel_spans.clear()
    otel_metrics.collect()
    response = await login(ds, "alice")
    assert response.status_code == 200

    verify = only(otel_spans, r.S_PASSWORD_VERIFY)
    kdf = only(otel_spans, r.S_PASSWORD_KDF)
    login_span = only(otel_spans, r.S_LOGIN)
    mint = only(otel_spans, r.S_MINT_SESSION)
    chores = only(otel_spans, r.S_HOUSEKEEPING)
    request_span = next(
        s for s in otel_spans.get_finished_spans() if s.name.startswith("POST ")
    )
    # verify and login are siblings under the request span.
    assert verify.parent.span_id == request_span.context.span_id
    assert login_span.parent.span_id == request_span.context.span_id
    assert kdf.parent.span_id == verify.context.span_id
    assert mint.parent.span_id == login_span.context.span_id
    assert chores.parent.span_id == login_span.context.span_id

    assert dict(verify.attributes) == {
        r.VERIFY_OUTCOME: "ok",
        r.VERIFY_KDF: "verify",
    }
    assert kdf.attributes[r.KDF_OPERATION] == "verify"
    assert dict(login_span.attributes) == {
        r.PROVIDER: "password",
        r.IDENTITY: "local",
        r.INTENT: "login",
        r.RESPONSE_MODE: "json",
        r.LOGIN_OUTCOME: "ok",
    }
    assert chores.attributes[r.TRIGGER] == "login"

    otel_metrics.collect()
    assert (
        otel_metrics.point(
            r.M_LOGINS, {r.PROVIDER: "password", r.LOGIN_OUTCOME: "ok"}
        ).value
        == 1
    )
    assert otel_metrics.points(r.M_LOGIN_DURATION, {r.IDENTITY: "local"})
    assert otel_metrics.points(r.M_KDF_DURATION, {r.KDF_OPERATION: "verify"})


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "setup,reason,kdf",
    [
        ("missing", "no_such_user", "dummy"),
        ("bad", "bad_password", "verify"),
        ("disabled", "disabled", "dummy"),
        ("expired", "expired", "dummy"),
        ("pending", "pending_approval", "dummy"),
        ("password_less", "no_password", "dummy"),
    ],
)
async def test_password_refusals(otel_spans, otel_metrics, setup, reason, kdf):
    ds = await make_ds()
    kwargs = {
        "disabled": {"disabled": True},
        "expired": {"expires_at": "2000-01-01T00:00:00.000+00:00"},
        "pending": {"pending": True},
        "password_less": {"password_less": True},
    }.get(setup, {})
    if setup != "missing":
        await insert_user(ds, "alice", **kwargs)
    otel_spans.clear()
    otel_metrics.collect()
    password = "wrong-password" if setup == "bad" else "password123"
    assert (await login(ds, "alice", password)).status_code == 401
    verify = only(otel_spans, r.S_PASSWORD_VERIFY)
    assert dict(verify.attributes) == {
        r.VERIFY_OUTCOME: "refused",
        r.REASON: reason,
        r.VERIFY_KDF: kdf,
    }
    # Refused before finish_login: no login span, no mint.
    assert ours(otel_spans, r.S_LOGIN) == []
    otel_metrics.collect()
    assert (
        otel_metrics.point(
            r.M_PASSWORD_VERIFICATIONS,
            {r.VERIFY_OUTCOME: "refused", r.REASON: reason},
        ).value
        == 1
    )
    assert otel_metrics.points(r.M_KDF_DURATION, {r.KDF_OPERATION: kdf})


@pytest.mark.asyncio
async def test_lockout_counted_once_at_threshold(otel_spans, otel_metrics):
    ds = await make_ds(lockout_threshold=2)
    await insert_user(ds, "alice")
    otel_metrics.collect()
    await login(ds, "alice", "wrong-1")
    otel_metrics.collect()
    assert otel_metrics.points(r.M_LOCKOUTS) == []
    await login(ds, "alice", "wrong-2")
    otel_metrics.collect()
    assert otel_metrics.point(r.M_LOCKOUTS).value == 1
    otel_spans.clear()
    assert (await login(ds, "alice")).status_code == 429
    verify = only(otel_spans, r.S_PASSWORD_VERIFY)
    # Locked refuses before hashing: no kdf attribute, no KDF span.
    assert dict(verify.attributes) == {
        r.VERIFY_OUTCOME: "refused",
        r.REASON: "locked",
    }
    assert ours(otel_spans, r.S_PASSWORD_KDF) == []
    otel_metrics.collect()
    assert otel_metrics.points(r.M_LOCKOUTS) == []


@pytest.mark.asyncio
async def test_finish_login_local_refusal(otel_spans):
    """finish_login's own gates (defence in depth behind the verify half)."""
    from providers_util import FakeRequest

    from datasette_accounts.providers import LocalIdentity, finish_login

    ds = await make_ds()
    uid = await insert_user(ds, "alice", disabled=True)
    otel_spans.clear()
    await finish_login(ds, FakeRequest(), LocalIdentity(uid), provider_key="password")
    span = only(otel_spans, r.S_LOGIN)
    assert span.attributes[r.LOGIN_OUTCOME] == "refused"
    assert span.attributes[r.REASON] == "disabled"
    assert span.attributes[r.RESPONSE_MODE] == "redirect"


@pytest.mark.asyncio
async def test_finish_login_error_outcome(otel_spans, otel_metrics):
    from providers_util import FakeRequest

    from datasette_accounts.providers import finish_login

    ds = await make_ds()
    otel_spans.clear()
    otel_metrics.collect()
    with pytest.raises(TypeError):
        await finish_login(ds, FakeRequest(), object(), provider_key="password")
    span = only(otel_spans, r.S_LOGIN)
    assert span.attributes[r.LOGIN_OUTCOME] == "error"
    assert span.attributes[r.ERROR_TYPE] == "TypeError"
    otel_metrics.collect()
    assert otel_metrics.point(r.M_LOGINS, {r.LOGIN_OUTCOME: "error"}).value == 1


@pytest.mark.asyncio
async def test_registration_outcomes(otel_metrics):
    ds = await make_ds(registrations_per_ip_per_day=2)

    async def submit(username, password="password123"):
        return await ds.client.post(
            "/-/register/api/submit",
            content=json.dumps({"username": username, "password": password}),
            headers=JSON,
        )

    internal = ds.get_internal_database()
    otel_metrics.collect()
    assert (await submit("newbie")).status_code == 404  # closed
    await db.set_registration_enabled(internal, "root", True)
    await insert_user(ds, "taken")
    assert (await submit("x")).status_code == 400  # invalid username
    assert (await submit("ok-user", "short")).status_code == 400  # invalid password
    assert (await submit("taken")).status_code == 409
    assert (await submit("newbie")).status_code == 200
    assert (await submit("another")).status_code == 429  # per-IP cap of 2
    otel_metrics.collect()

    def count(outcome, reason=None):
        attributes = {r.PROVIDER: "password", r.LOGIN_OUTCOME: outcome}
        if reason:
            attributes[r.REGISTRATION_REASON] = reason
        return total(otel_metrics, r.M_REGISTRATIONS, attributes)

    assert count("pending") == 1
    assert count("refused", "closed") == 1
    assert count("refused", "invalid") == 2
    assert count("refused", "taken") == 1
    assert count("refused", "capped") == 1
    assert otel_metrics.points(r.M_KDF_DURATION, {r.KDF_OPERATION: "hash"})


# --------------------------------------------------------------------------
# Provider surface: provider_gate + read_state
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_provider_gate_outcomes(otel_spans):
    ds = await make_ds()
    otel_spans.clear()
    assert (await ds.client.get("/-/demo-auth/start")).status_code == 404
    await enable_provider(ds, "demo")
    assert (await ds.client.post("/-/demo-auth/start")).status_code == 403
    assert (await ds.client.request("PUT", "/-/demo-auth/start")).status_code == 405
    assert (await ds.client.get("/-/demo-auth/start")).status_code == 302
    gates = [s.attributes[r.GATE] for s in ours(otel_spans, r.S_PROVIDER_ROUTE)]
    assert gates == ["disabled", "csrf", "method", "ok"]
    assert {s.attributes[r.PROVIDER] for s in ours(otel_spans, r.S_PROVIDER_ROUTE)} == {
        "demo"
    }


def _iso(delta):
    return (datetime.now(timezone.utc) + delta).isoformat(timespec="milliseconds")


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "cookie,arg,outcome",
    [
        (None, "abc", "missing"),
        ("garbage", "abc", "bad_signature"),
        ("string", "abc", "not_dict"),
        ({"s": "abc", "p": "demo"}, "zzz", "mismatch"),
        ({"s": "abc", "p": "other"}, "abc", "wrong_provider"),
        ({"s": "abc", "p": "demo", "c": "2000-01-01"}, "abc", "expired"),
    ],
)
async def test_state_read_outcomes(otel_spans, otel_metrics, cookie, arg, outcome):
    ds = await make_ds()
    await enable_provider(ds, "demo")
    if isinstance(cookie, dict):
        cookie = ds.sign({"c": _iso(timedelta()), **cookie}, STATE_NAMESPACE)
    elif cookie == "string":
        cookie = ds.sign("just-a-string", STATE_NAMESPACE)
    cookies = {STATE_COOKIE: cookie} if cookie else {}
    otel_spans.clear()
    otel_metrics.collect()
    response = await ds.client.get(
        f"/-/demo-auth/callback?state={arg}&subject=s&pin=1234", cookies=cookies
    )
    assert response.status_code == 400
    route = only(otel_spans, r.S_PROVIDER_ROUTE)
    assert route.attributes[r.STATE] == outcome
    otel_metrics.collect()
    assert otel_metrics.point(r.M_STATE_READS, {r.STATE: outcome}).value == 1


async def _demo_login(ds, subject, pin="1234"):
    start = await ds.client.get("/-/demo-auth/start")
    state = parse_qs(urlparse(start.headers["location"]).query)["state"][0]
    return await ds.client.get(
        f"/-/demo-auth/callback?state={state}&subject={subject}&pin={pin}",
        cookies={STATE_COOKIE: start.cookies.get(STATE_COOKIE)},
    )


@pytest.mark.asyncio
async def test_external_login_outcomes(otel_spans, otel_metrics):
    ds = await make_ds()
    internal = ds.get_internal_database()
    await enable_provider(ds, "demo")

    async def outcome_of(subject, signups):
        await db.set_provider_signups(internal, "root", "demo", signups)
        otel_spans.clear()
        await _demo_login(ds, subject)
        span = only(otel_spans, r.S_LOGIN)
        assert span.attributes[r.IDENTITY] == "external"
        assert span.attributes[r.PROVIDER] == "demo"
        # Nested under the callback's provider.route span (start has its own).
        routes = ours(otel_spans, r.S_PROVIDER_ROUTE)
        assert span.parent.span_id in {s.context.span_id for s in routes}
        return {
            k: v
            for k, v in span.attributes.items()
            if k in (r.LOGIN_OUTCOME, r.REASON, r.SIGNUPS)
        }

    otel_metrics.collect()
    assert await outcome_of("s-off", "off") == {
        r.LOGIN_OUTCOME: "refused",
        r.REASON: "provider_no_account",
        r.SIGNUPS: "off",
    }
    assert await outcome_of("s-approval", "approval") == {
        r.LOGIN_OUTCOME: "pending",
        r.SIGNUPS: "approval",
    }
    assert await outcome_of("s-auto", "auto") == {
        r.LOGIN_OUTCOME: "provisioned",
        r.SIGNUPS: "auto",
    }
    # Linked now: an ordinary login, the policy isn't consulted.
    assert await outcome_of("s-auto", "auto") == {r.LOGIN_OUTCOME: "ok"}
    # A fresh start is not a state failure; the callbacks' reads were ok.
    otel_metrics.collect()
    assert [p.attributes[r.STATE] for p in otel_metrics.points(r.M_STATE_READS)] == [
        "ok"
    ]
    assert total(otel_metrics, r.M_STATE_READS) == 4
    regs = {
        p.attributes[r.LOGIN_OUTCOME]: p.value
        for p in otel_metrics.points(r.M_REGISTRATIONS, {r.PROVIDER: "demo"})
    }
    assert regs == {"pending": 1, "ok": 1}


# --------------------------------------------------------------------------
# Housekeeping + startup
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_housekeeping_counts_purged_rows(otel_spans, otel_metrics):
    ds = await make_ds(admin_audit_retention_days=30)
    internal = ds.get_internal_database()
    uid = await insert_user(ds, "alice")
    await _expire_session(ds, uid)
    await session_cookie(ds, uid)  # a live one, kept
    await db.record_login_attempt(internal, "alice", "1.1.1.1", True, "success")
    await db.set_registration_enabled(internal, "root", True)  # an admin_audit row
    for table in (db.LOGIN_AUDIT, db.ADMIN_AUDIT):
        await internal.execute_write(
            f"UPDATE {table} SET timestamp = '2000-01-01T00:00:00.000+00:00'"
        )
    otel_spans.clear()
    otel_metrics.collect()
    await housekeeping(ds, trigger="startup")
    span = only(otel_spans, r.S_HOUSEKEEPING)
    assert dict(span.attributes) == {
        r.TRIGGER: "startup",
        r.PURGED_SESSIONS: 1,
        r.PURGED_PASSWORD_TOKENS: 0,
        r.PURGED_LOGIN_AUDIT: 1,
        r.PURGED_ADMIN_AUDIT: 1,
    }
    otel_metrics.collect()
    for table in ("sessions", "login_audit", "admin_audit"):
        point = otel_metrics.point(
            r.M_ROWS_PURGED, {r.PURGE_TABLE: table, r.TRIGGER: "startup"}
        )
        assert point.value == 1
    # Zero-row purges don't add a data point.
    assert (
        otel_metrics.points(r.M_ROWS_PURGED, {r.PURGE_TABLE: "password_tokens"}) == []
    )


@pytest.mark.asyncio
async def test_startup_spans(otel_spans):
    otel_spans.clear()
    await make_ds()
    assert only(otel_spans, r.S_HOUSEKEEPING).attributes[r.TRIGGER] == "startup"
    build = only(otel_spans, r.S_REGISTRY_BUILD)
    # The built-in password provider + the installed demo provider.
    assert build.attributes[r.PROVIDERS_INSTALLED] == 2
