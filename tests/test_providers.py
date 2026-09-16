"""The provider contract layer: hookspec/registry validation, signed state,
provider_gate, and finish_login's LocalIdentity gate matrix.

A test provider is registered through pluggy *before* make_ds() (the registry is
built at startup), then enabled by writing its settings row directly.
"""

import pytest
from datasette import Response
from datasette.app import Datasette
from providers_util import (
    JSON,
    FakeRequest,
    FakeResponse,
    cookie_cleared,
    enable_provider,
    insert_user,
    last_audit_reason,
    make_ds,
    session_count,
)

from datasette_accounts import db
from datasette_accounts.providers import (
    STATE_COOKIE,
    AuthProvider,
    LocalIdentity,
    finish_login,
    get_registry,
    make_state,
    read_state,
    start_state,
)
from datasette_accounts.security import COOKIE_NAME


# --------------------------------------------------------------------------
# Test providers
# --------------------------------------------------------------------------


class EchoProvider(AuthProvider):
    """A provider shaped like a real one: a descriptor plus explicit route
    handlers (mounted by the ``register_provider`` fixture), recording every
    call it receives."""

    key = "echo"
    label = "Echo"
    start_path = "/-/echo-auth/start"
    paths = ("start", "callback", "finish", "ping", "boom")

    def __init__(self):
        self.calls = []

    async def start(self, datasette, request):
        self.calls.append((request.method, "start"))
        resp = Response.redirect(datasette.urls.path("/-/echo-auth/callback"))
        value = make_state(
            datasette, request, resp, provider="echo", next=request.args.get("next")
        )
        resp.headers["Location"] = resp.headers["Location"] + "?state=" + value
        return resp

    async def callback(self, datasette, request):
        self.calls.append((request.method, "callback"))
        payload = read_state(datasette, request, provider="echo")
        if payload is None:
            return Response.json({"ok": False}, status=400)
        return Response.json({"ok": True, "state": payload})

    async def finish(self, datasette, request):
        self.calls.append((request.method, "finish"))
        return await finish_login(
            datasette,
            request,
            LocalIdentity(request.args.get("uid")),
            provider_key="echo",
            response_mode=request.args.get("mode") or "json",
        )

    async def ping(self, datasette, request):
        self.calls.append((request.method, "ping"))
        return Response.json({"ok": True, "method": request.method})

    async def boom(self, datasette, request):
        self.calls.append((request.method, "boom"))
        return Response.json({"ok": True, "method": request.method})


class _KeyProvider(AuthProvider):
    """A provider whose key is set per-test; startup rejects it before routing."""

    label = "Bad"
    start_path = "/-/bad-auth/start"

    def __init__(self, key):
        self.key = key


# --------------------------------------------------------------------------
# Registry validation
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_registry_includes_registered_provider(register_provider):
    provider = register_provider(EchoProvider())
    ds = await make_ds()
    registry = get_registry(ds)
    assert registry["echo"] is provider
    # The built-in password provider is always present and first. Filter to the
    # two keys under test so an incidentally-installed provider can't perturb it.
    keys = [k for k in registry if k in ("password", "echo")]
    assert keys == ["password", "echo"]


@pytest.mark.asyncio
async def test_builtin_password_provider_descriptor(register_provider):
    ds = await make_ds()
    password = get_registry(ds)["password"]
    assert password.key == "password"
    assert password.start_path == "/-/login"
    # Enabled by default (absent settings row); external providers are not.
    internal = ds.get_internal_database()
    assert await db.get_provider_enabled(internal, "password") is True
    assert await db.get_provider_enabled(internal, "echo") is False


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


class _StartPathProvider(AuthProvider):
    key = "sp"
    label = "SP"

    def __init__(self, start_path):
        self.start_path = start_path


@pytest.mark.asyncio
@pytest.mark.parametrize("start_path", [None, "", "relative/path"])
async def test_invalid_start_path_fails_startup(register_provider, start_path):
    register_provider(_StartPathProvider(start_path))
    with pytest.raises(RuntimeError, match="invalid start_path"):
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
    assert get_registry(ds)["branded"] is provider


# --------------------------------------------------------------------------
# provider_gate — the per-route enabled-bit / CSRF / method gate (D3b)
#
# Providers own their routes; provider_gate is the one-line decorator a
# provider wraps each route in to get the three guarantees design §3 asks of
# every provider route.
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_disabled_provider_route_404s(register_provider):
    register_provider(EchoProvider())
    ds = await make_ds()  # echo installed but NOT enabled
    disabled = await ds.client.get("/-/echo-auth/start")
    assert disabled.status_code == 404
    # Plain-text 404 body (see provider_gate's caveat: distinguishable from
    # Datasette's HTML 404 for a never-registered path — accepted, D3b).
    assert disabled.text == "Not found"


@pytest.mark.asyncio
async def test_enabled_provider_response_comes_back(register_provider):
    register_provider(EchoProvider())
    ds = await make_ds()
    await enable_provider(ds, "echo")
    r = await ds.client.get("/-/echo-auth/ping")
    assert r.status_code == 200
    assert r.json() == {"ok": True, "method": "GET"}


@pytest.mark.asyncio
async def test_post_without_csrf_rejected_before_handler(register_provider):
    provider = register_provider(EchoProvider())
    ds = await make_ds()
    await enable_provider(ds, "echo")
    # No application/json content-type → provider_gate's CSRF gate trips before
    # the handler runs.
    r = await ds.client.post("/-/echo-auth/boom", content="{}")
    assert r.status_code == 403
    assert provider.calls == []


@pytest.mark.asyncio
async def test_post_with_csrf_reaches_handler(register_provider):
    provider = register_provider(EchoProvider())
    ds = await make_ds()
    await enable_provider(ds, "echo")
    r = await ds.client.post("/-/echo-auth/boom", content="{}", headers=JSON)
    assert r.status_code == 200
    assert provider.calls == [("POST", "boom")]


@pytest.mark.asyncio
async def test_other_methods_405(register_provider):
    register_provider(EchoProvider())
    ds = await make_ds()
    await enable_provider(ds, "echo")
    r = await ds.client.put("/-/echo-auth/ping", content="{}", headers=JSON)
    assert r.status_code == 405


@pytest.mark.asyncio
async def test_head_request_dispatches_to_provider(register_provider):
    provider = register_provider(EchoProvider())
    ds = await make_ds()
    await enable_provider(ds, "echo")
    r = await ds.client.head("/-/echo-auth/ping")
    assert r.status_code == 200
    assert provider.calls == [("HEAD", "ping")]


# --------------------------------------------------------------------------
# Signed state round-trip
# --------------------------------------------------------------------------


async def _mint_state(ds, **kwargs):
    resp = FakeResponse()
    value = make_state(ds, FakeRequest(), resp, provider="echo", **kwargs)
    return value, resp.cookies[STATE_COOKIE][0]


@pytest.mark.asyncio
async def test_state_round_trip_returns_validated_next():
    ds = await make_ds()
    value, cookie = await _mint_state(ds, next="/dashboard")
    req = FakeRequest(cookies={STATE_COOKIE: cookie}, args={"state": value})
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
    req = FakeRequest(cookies={STATE_COOKIE: cookie}, args={"state": value})
    payload = read_state(ds, req, provider="echo")
    # `next` is validated at creation time — an off-origin target collapses to "/".
    assert payload["n"] == "/"


@pytest.mark.asyncio
async def test_state_tampered_cookie_is_none():
    ds = await make_ds()
    value, _cookie = await _mint_state(ds)
    req = FakeRequest(cookies={STATE_COOKIE: "garbage"}, args={"state": value})
    assert read_state(ds, req, provider="echo") is None


@pytest.mark.asyncio
async def test_state_mismatched_query_arg_is_none():
    ds = await make_ds()
    _value, cookie = await _mint_state(ds)
    req = FakeRequest(cookies={STATE_COOKIE: cookie}, args={"state": "wrong"})
    assert read_state(ds, req, provider="echo") is None


@pytest.mark.asyncio
async def test_state_missing_cookie_is_none():
    ds = await make_ds()
    value, _cookie = await _mint_state(ds)
    req = FakeRequest(cookies={}, args={"state": value})
    assert read_state(ds, req, provider="echo") is None


@pytest.mark.asyncio
async def test_state_wrong_provider_is_none():
    ds = await make_ds()
    value, cookie = await _mint_state(ds)
    req = FakeRequest(cookies={STATE_COOKIE: cookie}, args={"state": value})
    assert read_state(ds, req, provider="other") is None


@pytest.mark.asyncio
async def test_state_expired_is_none():
    # Re-sign a genuine payload with `created` pushed past the TTL window.
    ds = await make_ds(provider_state_ttl_minutes=1)
    value, cookie = await _mint_state(ds)
    payload = ds.unsign(cookie, "datasette-accounts-state")
    payload["c"] = "2000-01-01T00:00:00.000+00:00"
    stale = ds.sign(payload, "datasette-accounts-state")
    req = FakeRequest(cookies={STATE_COOKIE: stale}, args={"state": value})
    assert read_state(ds, req, provider="echo") is None


@pytest.mark.parametrize(
    "value",
    ["/\t/evil.com", "/%09/evil.com", "/\x0b/evil.com", "/%00/x", "/\x7f/x"],
)
def test_validate_next_rejects_control_characters(value):
    # Browsers strip tab / newline and treat other control characters loosely;
    # the guarantee must not hinge on how urlparse happens to tokenise them.
    from datasette_accounts.security import validate_next

    assert validate_next(value) == "/"


def test_make_state_refuses_unbound_link_intents():
    # Only core mints link / step-up states, and only bound to an actor: a
    # provider that copies `intent` out of the query string can't mint an
    # unbound linking state by mistake (it raises instead).
    ds = Datasette(memory=True)
    for intent in ("link", "step-up"):
        with pytest.raises(ValueError, match="bound to an actor_id"):
            make_state(
                ds, FakeRequest(), Response.text(""), provider="echo", intent=intent
            )
    with pytest.raises(ValueError, match="Unknown state intent"):
        make_state(
            ds, FakeRequest(), Response.text(""), provider="echo", intent="admin"
        )


@pytest.mark.asyncio
async def test_start_state_reuses_core_minted_state_else_mints_login():
    ds = await make_ds()
    # No state on the request → a fresh login-intent state is minted onto the
    # response (cookie set) and its value returned.
    resp = FakeResponse()
    value = start_state(ds, FakeRequest(), resp, provider="echo", next="/db")
    cookie = resp.cookies[STATE_COOKIE][0]
    payload = ds.unsign(cookie, "datasette-accounts-state")
    assert payload["s"] == value and payload["i"] == "login" and payload["n"] == "/db"
    # A valid core-minted state on the request (cookie + ?state=) is carried
    # through untouched — nothing re-minted, no cookie written.
    req = FakeRequest(cookies={STATE_COOKIE: cookie}, args={"state": value})
    resp2 = FakeResponse()
    assert start_state(ds, req, resp2, provider="echo") == value
    assert resp2.cookies == {}


@pytest.mark.asyncio
@pytest.mark.parametrize("ttl", [0, -1, "10", True, 2.5])
async def test_invalid_state_ttl_fails_startup(ttl):
    with pytest.raises(RuntimeError, match="provider_state_ttl_minutes"):
        await make_ds(provider_state_ttl_minutes=ttl)


@pytest.mark.asyncio
async def test_state_cookie_flags():
    ds = await make_ds()
    resp = FakeResponse()
    make_state(ds, FakeRequest(scheme="https"), resp, provider="echo", next="/x")
    _value, kw = resp.cookies[STATE_COOKIE]
    assert kw["httponly"] is True
    assert kw["samesite"] == "lax"
    # scheme https + secure_cookie "auto" → Secure set.
    assert kw["secure"] is True
    # provider_state_ttl_minutes default 10 → 600s.
    assert kw["max_age"] == 600
    assert kw["path"] == "/"


# --------------------------------------------------------------------------
# finish_login (LocalIdentity) — the gate matrix + mint
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_finish_login_local_happy_path(register_provider):
    register_provider(EchoProvider())
    ds = await make_ds()
    await enable_provider(ds, "echo")
    uid = await insert_user(ds, "alice")
    r = await ds.client.get(f"/-/echo-auth/finish?uid={uid}&mode=json")
    assert r.status_code == 200
    # Response shape is exactly what authenticate() returns today.
    assert r.json() == {"ok": True, "redirect": "/", "must_change_password": False}
    assert r.cookies.get(COOKIE_NAME)
    assert await session_count(ds) == 1


@pytest.mark.asyncio
async def test_finish_login_local_redirect_mode(register_provider):
    register_provider(EchoProvider())
    ds = await make_ds()
    await enable_provider(ds, "echo")
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
    await enable_provider(ds, "echo")
    uid = await insert_user(ds, "blocked", **kwargs)
    if pending:
        internal = ds.get_internal_database()
        await internal.execute_write(
            f"UPDATE {db.USERS} SET pending_approval = 1 WHERE id = ?", [uid]
        )
    r = await ds.client.get(f"/-/echo-auth/finish?uid={uid}&mode=json")
    assert r.status_code == 403
    assert r.json()["ok"] is False
    assert await session_count(ds) == 0
    assert await last_audit_reason(ds) == reason


@pytest.mark.asyncio
async def test_finish_login_nonexistent_user_refuses(register_provider):
    register_provider(EchoProvider())
    ds = await make_ds()
    await enable_provider(ds, "echo")
    r = await ds.client.get("/-/echo-auth/finish?uid=does-not-exist&mode=json")
    assert r.status_code == 403
    assert r.json()["ok"] is False
    assert await session_count(ds) == 0
    assert await last_audit_reason(ds) == "no_such_user"


@pytest.mark.asyncio
async def test_finish_login_revalidates_malicious_next_on_consumption():
    # The state's `next` is validated at creation AND re-validated here — an
    # off-origin target collapses to "/" even if it slipped into the state.
    ds = await make_ds()
    uid = await insert_user(ds, "alice")
    resp = await finish_login(
        ds,
        FakeRequest(),
        LocalIdentity(uid),
        provider_key="echo",
        response_mode="redirect",
        state={"n": "https://evil.example/pwn"},
    )
    assert resp.status == 302
    assert resp.headers["Location"] == "/"
    assert await session_count(ds) == 1


def _cookie_set(resp, name):
    """A live (non-clearing) Set-Cookie for `name`?"""
    return any(
        h.startswith(name + "=") and "Max-Age=0" not in h
        for h in resp._set_cookie_headers
    )


@pytest.mark.asyncio
async def test_finish_login_clears_state_and_sets_session_on_success():
    ds = await make_ds()
    uid = await insert_user(ds, "alice")
    resp = await finish_login(
        ds,
        FakeRequest(),
        LocalIdentity(uid),
        provider_key="echo",
        response_mode="json",
    )
    assert cookie_cleared(resp, STATE_COOKIE)
    assert _cookie_set(resp, COOKIE_NAME)


@pytest.mark.asyncio
async def test_refuse_clears_state_but_not_session():
    ds = await make_ds()
    uid = await insert_user(ds, "blocked", disabled=True)
    resp = await finish_login(
        ds,
        FakeRequest(),
        LocalIdentity(uid),
        provider_key="echo",
        response_mode="json",
    )
    assert resp.status == 403
    # State cookie is cleared on refusal...
    assert cookie_cleared(resp, STATE_COOKIE)
    # ...but the session cookie is neither set nor cleared (no session touched).
    assert not any(h.startswith(COOKIE_NAME + "=") for h in resp._set_cookie_headers)
