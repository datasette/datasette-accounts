"""Auth-provider hookspec, registry, mount, signed state, finish_login core.

These exercise the M1 skeleton (todos/auth-providers/01): a test provider is
registered through pluggy *before* make_ds() (the registry is built at startup),
then enabled by writing its settings row directly (the write helpers arrive in
ticket 05).
"""

import types

import pytest
from datasette import hookimpl
from datasette.app import Datasette
from datasette.plugins import pm

from datasette_accounts import db
from datasette_accounts.passwords import hash_password
from datasette_accounts.providers import (
    STATE_COOKIE,
    AuthProvider,
    LocalIdentity,
    finish_login,
    make_state,
    read_state,
)
from datasette_accounts.security import COOKIE_NAME

JSON = {"content-type": "application/json"}


async def make_ds(**plugin_config):
    metadata = {}
    if plugin_config:
        metadata = {"plugins": {"datasette-accounts": plugin_config}}
    ds = Datasette(memory=True, metadata=metadata)
    await ds.invoke_startup()
    return ds


async def insert_user(
    ds,
    username,
    password="password123",
    is_admin=False,
    disabled=False,
    must_change_password=False,
    expires_at=None,
):
    internal = ds.get_internal_database()
    user_id = db.new_id()
    ts = db.now_iso()
    await internal.execute_write(
        f"INSERT INTO {db.USERS} (id, username, password_hash, is_admin, disabled, "
        "must_change_password, failed_attempts, locked_until, created_at, updated_at, "
        "expires_at) "
        "VALUES (?, ?, ?, ?, ?, ?, 0, NULL, ?, ?, ?)",
        [
            user_id,
            username,
            hash_password(password),
            1 if is_admin else 0,
            1 if disabled else 0,
            1 if must_change_password else 0,
            ts,
            ts,
            expires_at,
        ],
    )
    return user_id


# --------------------------------------------------------------------------
# Test providers + registration helpers
# --------------------------------------------------------------------------


class EchoProvider(AuthProvider):
    key = "echo"
    label = "Echo"

    def __init__(self):
        self.calls = []

    async def handle(self, datasette, request, subpath):
        from datasette import Response

        self.calls.append((request.method, subpath))
        if subpath == "start":
            resp = Response.redirect(
                datasette.urls.path("/-/login/provider/echo/callback")
            )
            value = make_state(
                datasette, request, resp, provider="echo", next=request.args.get("next")
            )
            resp.headers["Location"] = resp.headers["Location"] + "?state=" + value
            return resp
        if subpath == "callback":
            payload = read_state(datasette, request, provider="echo")
            if payload is None:
                return Response.json({"ok": False}, status=400)
            return Response.json({"ok": True, "state": payload})
        if subpath == "finish":
            return await finish_login(
                datasette,
                request,
                LocalIdentity(request.args.get("uid")),
                provider_key="echo",
                response_mode=request.args.get("mode") or "json",
            )
        return Response.json(
            {"ok": True, "subpath": subpath, "method": request.method}
        )


class _KeyProvider(AuthProvider):
    """A provider whose key is set per-test; handle() must never run."""

    label = "Bad"

    def __init__(self, key):
        self.key = key

    async def handle(self, datasette, request, subpath):  # pragma: no cover
        raise AssertionError("handle should never run for a rejected key")


@pytest.fixture
def register_provider():
    """Register auth-provider plugins through pluggy; unregister on teardown."""
    names = []

    def _register(provider, name=None):
        name = name or f"test-provider-{len(names)}"
        mod = types.ModuleType(name)

        @hookimpl
        def datasette_accounts_auth_providers(datasette):
            return [provider]

        mod.datasette_accounts_auth_providers = datasette_accounts_auth_providers
        pm.register(mod, name=name)
        names.append(name)
        return provider

    yield _register
    for name in names:
        if pm.get_plugin(name) is not None:
            pm.unregister(name=name)


async def _enable_provider(ds, key):
    internal = ds.get_internal_database()
    await internal.execute_write(
        f"INSERT OR REPLACE INTO {db.SETTINGS} (key, value, updated_at) "
        "VALUES (?, '1', ?)",
        [f"provider:{key}:enabled", db.now_iso()],
    )


async def _session_count(ds):
    internal = ds.get_internal_database()
    rows = await internal.execute(f"SELECT COUNT(*) FROM {db.SESSIONS}")
    return rows.rows[0][0]


async def _last_audit_reason(ds):
    internal = ds.get_internal_database()
    rows = await internal.execute(
        f"SELECT reason FROM {db.LOGIN_AUDIT} ORDER BY rowid DESC LIMIT 1"
    )
    return rows.rows[0][0] if rows.rows else None


# --------------------------------------------------------------------------
# Registry validation
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_registry_includes_registered_provider(register_provider):
    provider = register_provider(EchoProvider())
    ds = await make_ds()
    registry = getattr(ds, "_datasette_accounts_providers")
    assert registry["echo"] is provider
    # The built-in password provider is always present and first.
    assert list(registry) == ["password", "echo"]


@pytest.mark.asyncio
async def test_duplicate_password_key_fails_startup(register_provider):
    register_provider(_KeyProvider("password"))
    with pytest.raises(RuntimeError, match="Duplicate auth provider key"):
        await make_ds()


@pytest.mark.asyncio
async def test_invalid_key_fails_startup(register_provider):
    register_provider(_KeyProvider("Echo!"))
    with pytest.raises(RuntimeError, match="Invalid auth provider key"):
        await make_ds()


# --------------------------------------------------------------------------
# Mount — resolution, enabled-bit, CSRF, method gate
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_unknown_and_disabled_providers_404_identically(register_provider):
    register_provider(EchoProvider())
    ds = await make_ds()  # echo installed but NOT enabled
    unknown = await ds.client.get("/-/login/provider/nope/start")
    disabled = await ds.client.get("/-/login/provider/echo/start")
    assert unknown.status_code == 404
    assert disabled.status_code == 404
    # Identical body — a disabled provider must be indistinguishable from an
    # uninstalled one.
    assert disabled.text == unknown.text


@pytest.mark.asyncio
async def test_enabled_provider_response_comes_back(register_provider):
    register_provider(EchoProvider())
    ds = await make_ds()
    await _enable_provider(ds, "echo")
    r = await ds.client.get("/-/login/provider/echo/ping")
    assert r.status_code == 200
    assert r.json() == {"ok": True, "subpath": "ping", "method": "GET"}


@pytest.mark.asyncio
async def test_post_without_csrf_rejected_before_handle(register_provider):
    provider = register_provider(EchoProvider())
    ds = await make_ds()
    await _enable_provider(ds, "echo")
    # No application/json content-type → CSRF gate trips before handle runs.
    r = await ds.client.post("/-/login/provider/echo/boom", content="{}")
    assert r.status_code == 403
    assert provider.calls == []


@pytest.mark.asyncio
async def test_post_with_csrf_reaches_handle(register_provider):
    provider = register_provider(EchoProvider())
    ds = await make_ds()
    await _enable_provider(ds, "echo")
    r = await ds.client.post(
        "/-/login/provider/echo/boom", content="{}", headers=JSON
    )
    assert r.status_code == 200
    assert provider.calls == [("POST", "boom")]


@pytest.mark.asyncio
async def test_other_methods_405(register_provider):
    register_provider(EchoProvider())
    ds = await make_ds()
    await _enable_provider(ds, "echo")
    r = await ds.client.put("/-/login/provider/echo/ping", content="{}", headers=JSON)
    assert r.status_code == 405


# --------------------------------------------------------------------------
# Signed state round-trip
# --------------------------------------------------------------------------


class _Args:
    def __init__(self, d):
        self._d = d

    def get(self, key, default=None):
        return self._d.get(key, default)


class _FakeRequest:
    def __init__(self, *, cookies=None, args=None, scheme="https", headers=None):
        self.cookies = cookies or {}
        self.args = _Args(args or {})
        self.scheme = scheme
        self.headers = headers or {}


class _FakeResponse:
    def __init__(self):
        self.cookies = {}

    def set_cookie(self, name, value="", **kw):
        self.cookies[name] = (value, kw)


async def _mint_state(ds, **kwargs):
    resp = _FakeResponse()
    value = make_state(ds, _FakeRequest(), resp, provider="echo", **kwargs)
    return value, resp.cookies[STATE_COOKIE][0]


@pytest.mark.asyncio
async def test_state_round_trip_returns_validated_next():
    ds = await make_ds()
    value, cookie = await _mint_state(ds, next="/dashboard")
    req = _FakeRequest(cookies={STATE_COOKIE: cookie}, args={"state": value})
    payload = read_state(ds, req, provider="echo")
    assert payload is not None
    assert payload["s"] == value
    assert payload["p"] == "echo"
    assert payload["n"] == "/dashboard"
    assert payload["i"] == "login"


@pytest.mark.asyncio
async def test_state_rejects_open_redirect_next():
    ds = await make_ds()
    value, cookie = await _mint_state(ds, next="https://evil.example/pwn")
    req = _FakeRequest(cookies={STATE_COOKIE: cookie}, args={"state": value})
    payload = read_state(ds, req, provider="echo")
    # `next` is validated at creation time — an off-origin target collapses to "/".
    assert payload["n"] == "/"


@pytest.mark.asyncio
async def test_state_tampered_cookie_is_none():
    ds = await make_ds()
    value, _cookie = await _mint_state(ds)
    req = _FakeRequest(cookies={STATE_COOKIE: "garbage"}, args={"state": value})
    assert read_state(ds, req, provider="echo") is None


@pytest.mark.asyncio
async def test_state_mismatched_query_arg_is_none():
    ds = await make_ds()
    _value, cookie = await _mint_state(ds)
    req = _FakeRequest(cookies={STATE_COOKIE: cookie}, args={"state": "wrong"})
    assert read_state(ds, req, provider="echo") is None


@pytest.mark.asyncio
async def test_state_wrong_provider_is_none():
    ds = await make_ds()
    value, cookie = await _mint_state(ds)
    req = _FakeRequest(cookies={STATE_COOKIE: cookie}, args={"state": value})
    assert read_state(ds, req, provider="other") is None


@pytest.mark.asyncio
async def test_state_expired_is_none():
    ds = await make_ds(provider_state_ttl_minutes=0)
    value, cookie = await _mint_state(ds)
    req = _FakeRequest(cookies={STATE_COOKIE: cookie}, args={"state": value})
    assert read_state(ds, req, provider="echo") is None


# --------------------------------------------------------------------------
# finish_login (LocalIdentity)
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_finish_login_local_happy_path(register_provider):
    register_provider(EchoProvider())
    ds = await make_ds()
    await _enable_provider(ds, "echo")
    uid = await insert_user(ds, "alice")
    r = await ds.client.get(f"/-/login/provider/echo/finish?uid={uid}&mode=json")
    assert r.status_code == 200
    # Response shape is exactly what authenticate() returns today.
    assert r.json() == {"ok": True, "redirect": "/", "must_change_password": False}
    assert r.cookies.get(COOKIE_NAME)
    assert await _session_count(ds) == 1


@pytest.mark.asyncio
async def test_finish_login_local_redirect_mode(register_provider):
    register_provider(EchoProvider())
    ds = await make_ds()
    await _enable_provider(ds, "echo")
    uid = await insert_user(ds, "alice")
    r = await ds.client.get(f"/-/login/provider/echo/finish?uid={uid}&mode=redirect")
    assert r.status_code == 302
    assert r.headers["location"] == "/"
    assert r.cookies.get(COOKIE_NAME)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "kwargs,pending,reason",
    [
        ({"disabled": True}, False, "disabled"),
        ({"expires_at": "2000-01-01T00:00:00.000+00:00"}, False, "expired"),
        ({}, True, "pending_approval"),
    ],
)
async def test_finish_login_local_gates_refuse(register_provider, kwargs, pending, reason):
    register_provider(EchoProvider())
    ds = await make_ds()
    await _enable_provider(ds, "echo")
    uid = await insert_user(ds, "blocked", **kwargs)
    if pending:
        internal = ds.get_internal_database()
        await internal.execute_write(
            f"UPDATE {db.USERS} SET pending_approval = 1 WHERE id = ?", [uid]
        )
    r = await ds.client.get(f"/-/login/provider/echo/finish?uid={uid}&mode=json")
    assert r.status_code == 403
    assert r.json()["ok"] is False
    assert await _session_count(ds) == 0
    assert await _last_audit_reason(ds) == reason
