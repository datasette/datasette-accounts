"""Auth-provider hookspec, registry, mount, signed state, finish_login core.

These exercise the M1 skeleton (todos/auth-providers/01): a test provider is
registered through pluggy *before* make_ds() (the registry is built at startup),
then enabled by writing its settings row directly (the write helpers arrive in
ticket 05).
"""

import json
import re
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
    provider_gate,
    read_state,
)
from datasette_accounts.security import COOKIE_NAME
from datasette_accounts.sessions import mint_token, token_sha256

JSON = {"content-type": "application/json"}

PAGE_DATA_RE = re.compile(
    r'<script type="application/json" id="pageData">(.*?)</script>', re.S
)


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
    start_path = "/-/echo-auth/start"

    def __init__(self):
        self.calls = []

    async def serve(self, datasette, request, subpath):
        from datasette import Response

        self.calls.append((request.method, subpath))
        if subpath == "start":
            resp = Response.redirect(datasette.urls.path("/-/echo-auth/callback"))
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
        return Response.json({"ok": True, "subpath": subpath, "method": request.method})


class _KeyProvider(AuthProvider):
    """A provider whose key is set per-test; startup rejects it before routing."""

    label = "Bad"
    start_path = "/-/bad-auth/start"

    def __init__(self, key):
        self.key = key


@pytest.fixture
def register_provider():
    """Register an auth provider AND its own routes (design D3b): the provider
    owns ``/-/{key}-auth/...`` via a normal ``register_routes`` hook, each route
    wrapped in ``provider_gate`` for the enabled-404 + CSRF gate. Unregister on
    teardown."""
    names = []

    def _register(provider, name=None):
        name = name or f"test-provider-{len(names)}"
        mod = types.ModuleType(name)

        @hookimpl
        def datasette_accounts_auth_providers(datasette):
            return [provider]

        @provider_gate(provider.key)
        async def _view(datasette, request):
            return await provider.serve(datasette, request, request.url_vars["rest"])

        @hookimpl
        def register_routes():
            return [(rf"/-/{provider.key}-auth/(?P<rest>.*)$", _view)]

        mod.datasette_accounts_auth_providers = datasette_accounts_auth_providers
        mod.register_routes = register_routes
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
    # The built-in password provider is always present and first. (The installed
    # datasette-accounts-demo-auth example package also contributes a `demo`
    # provider to every startup — ignore it here.)
    keys = [k for k in registry if k != "demo"]
    assert keys == ["password", "echo"]


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


class _BrandedProvider(AuthProvider):
    """Optional branding set per-test, so startup validation can be probed."""

    key = "branded"
    label = "Branded"
    start_path = "/-/branded-auth/start"

    def __init__(self, icon=None, brand_color=None):
        self.icon = icon
        self.brand_color = brand_color


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "icon",
    [
        "not svg at all",
        '<img src="x.png">',
        # Well-formed wrapper, but smuggles a <script> element.
        "<svg><script>alert(1)</script></svg>",
        # Truncated — no closing tag.
        "<svg><path d='M0 0'/>",
    ],
)
async def test_invalid_icon_fails_startup(register_provider, icon):
    register_provider(_BrandedProvider(icon=icon))
    with pytest.raises(RuntimeError, match="invalid icon"):
        await make_ds()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "brand_color",
    ["blurple", "#12345", "rgb(88, 101, 242)", "#5865F2; background:url(x)"],
)
async def test_invalid_brand_color_fails_startup(register_provider, brand_color):
    register_provider(_BrandedProvider(brand_color=brand_color))
    with pytest.raises(RuntimeError, match="invalid brand_color"):
        await make_ds()


@pytest.mark.asyncio
async def test_valid_branding_accepted_at_startup(register_provider):
    provider = _BrandedProvider(
        icon='<svg xmlns="http://www.w3.org/2000/svg"><path d="M0 0h16"/></svg>',
        brand_color="#5865F2",
    )
    register_provider(provider)
    ds = await make_ds()
    assert getattr(ds, "_datasette_accounts_providers")["branded"] is provider


# --------------------------------------------------------------------------
# provider_gate — the per-route enabled-bit / CSRF / method gate (D3b)
#
# Providers own their routes now; there is no core mount. provider_gate is the
# one-line decorator a provider wraps each route in to get the same three
# guarantees the old mount enforced centrally. "Unknown provider 404s" is gone:
# an unregistered path is now Datasette's ordinary 404.
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_disabled_provider_route_404s(register_provider):
    register_provider(EchoProvider())
    ds = await make_ds()  # echo installed but NOT enabled
    disabled = await ds.client.get("/-/echo-auth/start")
    assert disabled.status_code == 404
    # Same body the old mount used, so a disabled provider is indistinguishable
    # from an uninstalled one.
    assert disabled.text == "Not found"


@pytest.mark.asyncio
async def test_enabled_provider_response_comes_back(register_provider):
    register_provider(EchoProvider())
    ds = await make_ds()
    await _enable_provider(ds, "echo")
    r = await ds.client.get("/-/echo-auth/ping")
    assert r.status_code == 200
    assert r.json() == {"ok": True, "subpath": "ping", "method": "GET"}


@pytest.mark.asyncio
async def test_post_without_csrf_rejected_before_handler(register_provider):
    provider = register_provider(EchoProvider())
    ds = await make_ds()
    await _enable_provider(ds, "echo")
    # No application/json content-type → provider_gate's CSRF gate trips before
    # the handler runs.
    r = await ds.client.post("/-/echo-auth/boom", content="{}")
    assert r.status_code == 403
    assert provider.calls == []


@pytest.mark.asyncio
async def test_post_with_csrf_reaches_handler(register_provider):
    provider = register_provider(EchoProvider())
    ds = await make_ds()
    await _enable_provider(ds, "echo")
    r = await ds.client.post("/-/echo-auth/boom", content="{}", headers=JSON)
    assert r.status_code == 200
    assert provider.calls == [("POST", "boom")]


@pytest.mark.asyncio
async def test_other_methods_405(register_provider):
    register_provider(EchoProvider())
    ds = await make_ds()
    await _enable_provider(ds, "echo")
    r = await ds.client.put("/-/echo-auth/ping", content="{}", headers=JSON)
    assert r.status_code == 405


@pytest.mark.asyncio
async def test_ungated_route_on_disabled_provider_cannot_mint():
    """CRITICAL regression (D3b): provider_gate is optional, so a provider could
    forget it. finish_login's enabled re-check — NOT the (now-removed) mount — is
    the load-bearing control: a disabled provider whose route SKIPS provider_gate
    still cannot mint. The ungated handler RUNS (no 404), but finish_login refuses
    with a 403, writes provider_disabled, and mints no session."""
    from datasette import Response  # noqa: F401  (kept parallel with other tests)
    from datasette_accounts.providers import ExternalIdentity

    class UngatedProvider(AuthProvider):
        key = "ungated"
        label = "Ungated"
        start_path = "/-/ungated-auth/start"

    provider = UngatedProvider()
    mod = types.ModuleType("ungated-provider")

    @hookimpl
    def datasette_accounts_auth_providers(datasette):
        return [provider]

    async def _ungated_view(datasette, request):
        # Deliberately NOT wrapped in @provider_gate: hand an external identity
        # straight to finish_login and let the core gate decide.
        return await finish_login(
            datasette,
            request,
            ExternalIdentity(provider="ungated", subject="s-1"),
            provider_key="ungated",
            response_mode="json",
        )

    @hookimpl
    def register_routes():
        return [(r"/-/ungated-auth/(?P<rest>.*)$", _ungated_view)]

    mod.datasette_accounts_auth_providers = datasette_accounts_auth_providers
    mod.register_routes = register_routes
    pm.register(mod, name="ungated-provider")
    try:
        ds = await make_ds()  # ungated provider installed but NOT enabled
        # Even a genuinely-linked identity must be refused while disabled.
        uid = await insert_user(ds, "alice")
        internal = ds.get_internal_database()
        await internal.execute_write(
            f"INSERT INTO {db.IDENTITIES} (provider, subject, user_id, created_at) "
            "VALUES (?, ?, ?, ?)",
            ["ungated", "s-1", uid, db.now_iso()],
        )
        # The ungated route RUNS — a provider_gate would have 404'd here...
        r = await ds.client.get("/-/ungated-auth/callback")
        # ...but finish_login's enabled re-check refuses: 403, no session.
        assert r.status_code == 403
        assert await _session_count(ds) == 0
        assert await _last_audit_reason(ds) == "provider_disabled"
    finally:
        if pm.get_plugin("ungated-provider") is not None:
            pm.unregister(name="ungated-provider")


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
    r = await ds.client.get(f"/-/echo-auth/finish?uid={uid}&mode=json")
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
    r = await ds.client.get(f"/-/echo-auth/finish?uid={uid}&mode=redirect")
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
async def test_finish_login_local_gates_refuse(
    register_provider, kwargs, pending, reason
):
    register_provider(EchoProvider())
    ds = await make_ds()
    await _enable_provider(ds, "echo")
    uid = await insert_user(ds, "blocked", **kwargs)
    if pending:
        internal = ds.get_internal_database()
        await internal.execute_write(
            f"UPDATE {db.USERS} SET pending_approval = 1 WHERE id = ?", [uid]
        )
    r = await ds.client.get(f"/-/echo-auth/finish?uid={uid}&mode=json")
    assert r.status_code == 403
    assert r.json()["ok"] is False
    assert await _session_count(ds) == 0
    assert await _last_audit_reason(ds) == reason


# --------------------------------------------------------------------------
# Password provider — the built-in provider (ticket 02)
# --------------------------------------------------------------------------


async def _disable_provider(ds, key):
    internal = ds.get_internal_database()
    await internal.execute_write(
        f"INSERT OR REPLACE INTO {db.SETTINGS} (key, value, updated_at) "
        "VALUES (?, '0', ?)",
        [f"provider:{key}:enabled", db.now_iso()],
    )


def _page_data(resp):
    m = PAGE_DATA_RE.search(resp.text)
    assert m, "no #pageData script tag found"
    return json.loads(m.group(1))


@pytest.mark.asyncio
async def test_password_disabled_takes_login_surface_offline():
    ds = await make_ds()
    await insert_user(ds, "alice")
    internal = ds.get_internal_database()
    await db.set_registration_enabled(internal, "root", True)
    await _disable_provider(ds, "password")

    # The login page reports the disabled state (frontend drops the form — 06).
    page = await ds.client.get("/-/login")
    assert _page_data(page)["password_enabled"] is False

    # The canonical authenticate endpoint 404s before any KDF work.
    r = await ds.client.post(
        "/-/login/api/authenticate",
        content=json.dumps({"username": "alice", "password": "password123"}),
        headers=JSON,
    )
    assert r.status_code == 404
    assert not r.cookies.get(COOKIE_NAME)

    # Registration is closed even though the signups toggle is on: a disabled
    # password provider means no password signups at all.
    assert (await ds.client.get("/-/register")).status_code == 404
    sub = await ds.client.post(
        "/-/register/api/submit",
        content=json.dumps({"username": "newperson", "password": "password123"}),
        headers=JSON,
    )
    assert sub.status_code == 404


@pytest.mark.asyncio
async def test_invite_completion_works_while_password_disabled():
    # An invite/reset link is an admin act; completing one stays available even
    # when password login is disabled (design §8 / M2).
    ds = await make_ds()
    await _disable_provider(ds, "password")
    internal = ds.get_internal_database()
    raw = mint_token()
    await db.create_invited_user(
        internal, "root", "invitee", False, token_sha256(raw), 72
    )

    r = await ds.client.post(
        "/-/set-password/api/complete",
        content=json.dumps({"token": raw, "new_password": "brand-new-pass1"}),
        headers=JSON,
    )
    assert r.status_code == 200
    # Response shape is unchanged (no must_change_password key added).
    assert r.json() == {"ok": True, "redirect": "/"}
    # A real session was minted despite password login being off.
    assert r.cookies.get(COOKIE_NAME)
    assert await _session_count(ds) == 1


@pytest.mark.asyncio
async def test_password_reenable_takes_effect_without_restart():
    ds = await make_ds()
    await insert_user(ds, "alice")
    await _disable_provider(ds, "password")
    off = await ds.client.post(
        "/-/login/api/authenticate",
        content=json.dumps({"username": "alice", "password": "password123"}),
        headers=JSON,
    )
    assert off.status_code == 404

    # Flip the runtime row back to '1' — no restart, same ds instance.
    await _enable_provider(ds, "password")
    on = await ds.client.post(
        "/-/login/api/authenticate",
        content=json.dumps({"username": "alice", "password": "password123"}),
        headers=JSON,
    )
    assert on.status_code == 200
    assert on.json()["ok"] is True
    assert on.cookies.get(COOKIE_NAME)


# --------------------------------------------------------------------------
# finish_login / mount — hardening (security review of ticket 01)
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_state_cookie_flags():
    ds = await make_ds()
    resp = _FakeResponse()
    make_state(ds, _FakeRequest(scheme="https"), resp, provider="echo", next="/x")
    _value, kw = resp.cookies[STATE_COOKIE]
    assert kw["httponly"] is True
    assert kw["samesite"] == "lax"
    # scheme https + secure_cookie "auto" → Secure set.
    assert kw["secure"] is True
    # provider_state_ttl_minutes default 10 → 600s.
    assert kw["max_age"] == 600
    assert kw["path"] == "/"


@pytest.mark.asyncio
async def test_finish_login_nonexistent_user_refuses(register_provider):
    register_provider(EchoProvider())
    ds = await make_ds()
    await _enable_provider(ds, "echo")
    r = await ds.client.get("/-/echo-auth/finish?uid=does-not-exist&mode=json")
    assert r.status_code == 403
    assert r.json()["ok"] is False
    assert await _session_count(ds) == 0
    assert await _last_audit_reason(ds) == "no_such_user"


@pytest.mark.asyncio
async def test_finish_login_revalidates_malicious_next_on_consumption():
    # The state's `next` is validated at creation AND re-validated here — an
    # off-origin target collapses to "/" even if it slipped into the state.
    ds = await make_ds()
    uid = await insert_user(ds, "alice")
    resp = await finish_login(
        ds,
        _FakeRequest(),
        LocalIdentity(uid),
        provider_key="echo",
        response_mode="redirect",
        state={"n": "https://evil.example/pwn"},
    )
    assert resp.status == 302
    assert resp.headers["Location"] == "/"
    assert await _session_count(ds) == 1


def _cookie_set(resp, name):
    """A live (non-clearing) Set-Cookie for `name`?"""
    return any(
        h.startswith(name + "=") and "Max-Age=0" not in h
        for h in resp._set_cookie_headers
    )


def _cookie_cleared(resp, name):
    return any(
        h.startswith(name + "=") and "Max-Age=0" in h for h in resp._set_cookie_headers
    )


@pytest.mark.asyncio
async def test_finish_login_clears_state_and_sets_session_on_success():
    ds = await make_ds()
    uid = await insert_user(ds, "alice")
    resp = await finish_login(
        ds,
        _FakeRequest(),
        LocalIdentity(uid),
        provider_key="echo",
        response_mode="json",
    )
    assert _cookie_cleared(resp, STATE_COOKIE)
    assert _cookie_set(resp, COOKIE_NAME)


@pytest.mark.asyncio
async def test_refuse_clears_state_but_not_session():
    ds = await make_ds()
    uid = await insert_user(ds, "blocked", disabled=True)
    resp = await finish_login(
        ds,
        _FakeRequest(),
        LocalIdentity(uid),
        provider_key="echo",
        response_mode="json",
    )
    assert resp.status == 403
    # State cookie is cleared on refusal...
    assert _cookie_cleared(resp, STATE_COOKIE)
    # ...but the session cookie is neither set nor cleared (no session touched).
    assert not any(h.startswith(COOKIE_NAME + "=") for h in resp._set_cookie_headers)


@pytest.mark.asyncio
async def test_head_request_dispatches_to_provider(register_provider):
    provider = register_provider(EchoProvider())
    ds = await make_ds()
    await _enable_provider(ds, "echo")
    r = await ds.client.head("/-/echo-auth/ping")
    assert r.status_code == 200
    assert provider.calls == [("HEAD", "ping")]


# --------------------------------------------------------------------------
# Admin set-provider endpoint + config page data (ticket 05)
# --------------------------------------------------------------------------


async def _admin_cookies(ds, username="boss"):
    """Create an admin, log in through the real endpoint, return its cookies."""
    await insert_user(ds, username, is_admin=True)
    r = await ds.client.post(
        "/-/login/api/authenticate",
        content=json.dumps({"username": username, "password": "password123"}),
        headers=JSON,
    )
    cookie = r.cookies.get(COOKIE_NAME)
    return {COOKIE_NAME: cookie} if cookie else {}


async def _set_provider(ds, cookies, **body):
    return await ds.client.post(
        "/-/admin/api/set-provider",
        content=json.dumps(body),
        headers=JSON,
        cookies=cookies,
    )


@pytest.mark.asyncio
async def test_set_provider_enables_and_takes_effect_next_request(register_provider):
    register_provider(EchoProvider())
    ds = await make_ds()
    cookies = await _admin_cookies(ds)

    # Disabled at first: the mount 404s.
    assert (await ds.client.get("/-/echo-auth/ping")).status_code == 404

    on = await _set_provider(ds, cookies, key="echo", enabled=True)
    assert on.status_code == 200
    assert on.json() == {"ok": True, "enabled": True, "signups": "off"}

    # Live on the very next request — no restart.
    assert (await ds.client.get("/-/echo-auth/ping")).status_code == 200

    off = await _set_provider(ds, cookies, key="echo", enabled=False)
    assert off.json()["enabled"] is False
    assert (await ds.client.get("/-/echo-auth/ping")).status_code == 404


@pytest.mark.asyncio
async def test_set_provider_signups_only(register_provider):
    register_provider(EchoProvider())
    ds = await make_ds()
    cookies = await _admin_cookies(ds)
    r = await _set_provider(ds, cookies, key="echo", signups="approval")
    assert r.status_code == 200
    assert r.json() == {"ok": True, "enabled": False, "signups": "approval"}
    internal = ds.get_internal_database()
    assert await db.get_provider_signups(internal, "echo") == "approval"


@pytest.mark.asyncio
async def test_set_provider_requires_admin(register_provider):
    register_provider(EchoProvider())
    ds = await make_ds()
    await insert_user(ds, "alice")  # not an admin
    r = await ds.client.post(
        "/-/login/api/authenticate",
        content=json.dumps({"username": "alice", "password": "password123"}),
        headers=JSON,
    )
    cookies = {COOKIE_NAME: r.cookies.get(COOKIE_NAME)}
    resp = await _set_provider(ds, cookies, key="echo", enabled=True)
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_set_provider_unknown_key_400(register_provider):
    register_provider(EchoProvider())
    ds = await make_ds()
    cookies = await _admin_cookies(ds)
    resp = await _set_provider(ds, cookies, key="nope", enabled=True)
    assert resp.status_code == 400
    assert resp.json()["ok"] is False


@pytest.mark.asyncio
async def test_set_provider_invalid_signups_400(register_provider):
    register_provider(EchoProvider())
    ds = await make_ds()
    cookies = await _admin_cookies(ds)
    resp = await _set_provider(ds, cookies, key="echo", signups="sometimes")
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_set_provider_last_provider_guard(register_provider):
    register_provider(EchoProvider())
    ds = await make_ds()
    cookies = await _admin_cookies(ds)

    # Only password is enabled → disabling it is refused.
    refuse = await _set_provider(ds, cookies, key="password", enabled=False)
    assert refuse.status_code == 400
    assert refuse.json()["error"] == "Cannot disable the last sign-in provider."

    # Enable echo, then password may be disabled...
    await _set_provider(ds, cookies, key="echo", enabled=True)
    ok = await _set_provider(ds, cookies, key="password", enabled=False)
    assert ok.status_code == 200

    # ...but now echo is the last one and cannot be disabled.
    refuse2 = await _set_provider(ds, cookies, key="echo", enabled=False)
    assert refuse2.status_code == 400


@pytest.mark.asyncio
async def test_set_provider_noop_writes_one_audit_row(register_provider):
    register_provider(EchoProvider())
    ds = await make_ds()
    cookies = await _admin_cookies(ds)
    await _set_provider(ds, cookies, key="echo", enabled=True)
    await _set_provider(ds, cookies, key="echo", enabled=True)  # no-op
    internal = ds.get_internal_database()
    rows = (
        await internal.execute(
            f"SELECT operation FROM {db.ADMIN_AUDIT} "
            "WHERE operation = 'enable-provider'"
        )
    ).rows
    assert len(rows) == 1


@pytest.mark.asyncio
async def test_config_page_data_has_provider_rows(register_provider):
    register_provider(EchoProvider())
    ds = await make_ds()
    cookies = await _admin_cookies(ds)
    internal = ds.get_internal_database()
    # One linked identity for echo → linked_count == 1.
    uid = await insert_user(ds, "carol")
    await internal.execute_write(
        f"INSERT INTO {db.IDENTITIES} "
        "(provider, subject, user_id, created_at) VALUES (?, ?, ?, ?)",
        ["echo", "sub-1", uid, db.now_iso()],
    )
    await _set_provider(ds, cookies, key="echo", enabled=True, signups="approval")

    page = await ds.client.get("/-/admin/config", cookies=cookies)
    data = _page_data(page)
    providers = {p["key"]: p for p in data["providers"]}
    assert providers["password"]["builtin"] is True
    assert providers["password"]["enabled"] is True
    assert providers["password"]["linked_count"] == 0
    assert providers["echo"]["builtin"] is False
    assert providers["echo"]["enabled"] is True
    assert providers["echo"]["signups"] == "approval"
    assert providers["echo"]["linked_count"] == 1
    # Source = the provider class's top-level module (this test file).
    assert providers["echo"]["source"] == "test_providers"
    assert providers["password"]["source"] == "datasette_accounts"
