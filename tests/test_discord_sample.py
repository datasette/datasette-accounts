"""Unit coverage for the Discord OAuth2 sample (samples/discord-auth).

Ticket todos/auth-providers/08. The sample is a *real* OAuth2 provider, so unlike
the demo (a browser-only fake IdP) its callback exchanges a code for a token and
reads the Discord user over HTTP. respx is not a dev dependency here, so we
monkeypatch ``httpx.AsyncClient`` with a tiny fake that returns canned token + me
responses — the provider's own HTTP calls never leave the process.

The module is loaded exactly as ``just dev`` loads it: via Datasette's
``plugins_dir`` (a loose ``.py`` file), NOT an installed distribution. Enabling +
signups go through the real ticket-05 db functions, as the admin UI / CLI would.
"""

import types
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import pytest
from datasette.app import Datasette

from datasette_accounts import db
from datasette_accounts.providers import STATE_COOKIE, get_registry
from datasette_accounts.security import COOKIE_NAME

SAMPLE_DIR = str(Path(__file__).resolve().parent.parent / "samples" / "discord-auth")

# Canned Discord responses the fake AsyncClient returns.
DISCORD_ME = {
    "id": "80351110224678912",  # a snowflake — THE stable id
    "username": "nelly",
    "global_name": "Nelly",
    "email": "nelly@example.com",
}


class _FakeResponse:
    def __init__(self, data):
        self._data = data

    def json(self):
        return self._data

    def raise_for_status(self):
        return None


class _FakeAsyncClient:
    """Stand-in for httpx.AsyncClient: async context manager whose post()/get()
    return the canned token-exchange + /users/@me payloads."""

    def __init__(self, *args, **kwargs):
        self.posts = []
        self.gets = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def post(self, url, data=None, **kwargs):
        self.posts.append((url, data))
        return _FakeResponse({"access_token": "fake-access-token", "token_type": "Bearer"})

    async def get(self, url, headers=None, **kwargs):
        self.gets.append((url, headers))
        return _FakeResponse(DISCORD_ME)


@pytest.fixture(autouse=True)
def _unregister_sample():
    """Datasette's plugins_dir loader registers ``discord_auth.py`` into the
    global pluggy manager and never removes it, which would leak the discord
    provider into every later test's registry (test_providers asserts exact
    keys). Unregister it after each test so the loaded sample is scoped here."""
    from datasette.plugins import pm

    yield
    if pm.has_plugin("discord_auth.py"):
        pm.unregister(name="discord_auth.py")


async def _make_ds():
    ds = Datasette(memory=True, plugins_dir=SAMPLE_DIR)
    await ds.invoke_startup()
    return ds


def _mock_httpx(ds, monkeypatch):
    """Swap ONLY the discord_auth module's ``httpx`` reference for a shim exposing
    the fake AsyncClient. Patching the global ``httpx.AsyncClient`` would break
    Datasette's own httpx-based test client, so we target the module globals of
    the loaded provider (a loose plugins_dir file, absent from sys.modules under
    an importable name) via its ``callback`` route handler's ``__globals__`` —
    the provider now owns its routes (design D3b), so the handler is a
    module-level function, not the old dispatch method."""
    from datasette.plugins import pm

    module = pm.get_plugin("discord_auth.py")  # the loose plugins_dir module
    # ``callback`` is wrapped by @provider_gate, whose wrapper lives in the core
    # providers module; ``__wrapped__`` is the sample's own handler, so its
    # ``__globals__`` is the discord_auth module namespace where ``httpx`` lives.
    module_globals = module.callback.__wrapped__.__globals__
    monkeypatch.setitem(
        module_globals, "httpx", types.SimpleNamespace(AsyncClient=_FakeAsyncClient)
    )


async def _enable(ds, *, signups=None):
    internal = ds.get_internal_database()
    installed = list(get_registry(ds))
    await db.set_provider_enabled(
        internal, "root", "discord", True, installed_keys=installed
    )
    if signups is not None:
        await db.set_provider_signups(internal, "root", "discord", signups)


def _configure_env(monkeypatch):
    monkeypatch.setenv("DATASETTE_DISCORD_CLIENT_ID", "client-abc")
    monkeypatch.setenv("DATASETTE_DISCORD_CLIENT_SECRET", "secret-xyz")


# ==========================================================================
# 1. Discovery + disabled-by-default
# ==========================================================================


@pytest.mark.asyncio
async def test_discord_discovered_via_plugins_dir():
    ds = await _make_ds()
    registry = get_registry(ds)
    assert "discord" in registry
    assert registry["discord"].label == "Discord"
    from datasette_accounts.providers import provider_source

    assert provider_source(registry["discord"]) == "discord_auth"


@pytest.mark.asyncio
async def test_disabled_by_default_mount_404s():
    ds = await _make_ds()  # loaded but never enabled
    for sub in ("start", "callback"):
        r = await ds.client.get(f"/-/discord-auth/{sub}")
        assert r.status_code == 404, sub


# ==========================================================================
# 2. start — unconfigured 503, configured 302 to discord.com
# ==========================================================================


@pytest.mark.asyncio
async def test_start_unconfigured_returns_503(monkeypatch):
    monkeypatch.delenv("DATASETTE_DISCORD_CLIENT_ID", raising=False)
    monkeypatch.delenv("DATASETTE_DISCORD_CLIENT_SECRET", raising=False)
    ds = await _make_ds()
    await _enable(ds, signups="auto")
    r = await ds.client.get("/-/discord-auth/start")
    assert r.status_code == 503
    assert "not configured" in r.text


@pytest.mark.asyncio
async def test_start_configured_redirects_to_discord(monkeypatch):
    _configure_env(monkeypatch)
    ds = await _make_ds()
    await _enable(ds, signups="auto")

    r = await ds.client.get("/-/discord-auth/start?next=/-/account")
    assert r.status_code == 302
    location = r.headers["location"]
    assert location.startswith("https://discord.com/oauth2/authorize?")
    q = parse_qs(urlparse(location).query)
    assert q["client_id"] == ["client-abc"]
    assert q["response_type"] == ["code"]
    assert q["scope"] == ["identify"]
    assert q["redirect_uri"][0].endswith("/-/discord-auth/callback")
    # The state is core-minted: it round-trips through the state cookie.
    state_cookie = r.cookies.get(STATE_COOKIE)
    assert state_cookie
    assert q["state"][0]  # present + non-empty


# ==========================================================================
# 3. callback — mocked token + me responses provision an account (auto)
# ==========================================================================


async def _drive_start(ds):
    """Drive start → return (state_value, cookies) for a callback."""
    r = await ds.client.get("/-/discord-auth/start")
    assert r.status_code == 302
    state = parse_qs(urlparse(r.headers["location"]).query)["state"][0]
    return state, {STATE_COOKIE: r.cookies.get(STATE_COOKIE)}


@pytest.mark.asyncio
async def test_callback_auto_provisions_and_mints(monkeypatch):
    _configure_env(monkeypatch)
    ds = await _make_ds()
    _mock_httpx(ds, monkeypatch)
    await _enable(ds, signups="auto")
    internal = ds.get_internal_database()

    state, cookies = await _drive_start(ds)
    r = await ds.client.get(
        f"/-/discord-auth/callback?state={state}&code=oauth-code",
        cookies=cookies,
    )
    assert r.status_code == 302
    session = r.cookies.get(COOKIE_NAME)
    assert session  # a real session was minted on the discord provenance

    # The identity was keyed on the snowflake id (never the username/email).
    ident = await db.get_identity(internal, "discord", DISCORD_ME["id"])
    assert ident is not None
    user = await db.get_user_by_id(internal, ident["user_id"])
    assert user["username"] == "nelly"  # derived from username_hint
    assert user["pending_approval"] == 0

    srows = await internal.execute(f"SELECT provider FROM {db.SESSIONS}")
    assert [row[0] for row in srows.rows] == ["discord"]
    last = await internal.execute(
        f"SELECT reason, provider FROM {db.LOGIN_AUDIT} ORDER BY id DESC LIMIT 1"
    )
    assert dict(last.rows[0]) == {"reason": "success", "provider": "discord"}


@pytest.mark.asyncio
async def test_callback_without_state_fails(monkeypatch):
    _configure_env(monkeypatch)
    ds = await _make_ds()
    _mock_httpx(ds, monkeypatch)
    await _enable(ds, signups="auto")
    # No state cookie / query arg → read_state guard trips before any HTTP call.
    r = await ds.client.get("/-/discord-auth/callback?code=x")
    assert r.status_code == 400


@pytest.mark.asyncio
async def test_callback_without_code_fails(monkeypatch):
    _configure_env(monkeypatch)
    ds = await _make_ds()
    _mock_httpx(ds, monkeypatch)
    await _enable(ds, signups="auto")
    state, cookies = await _drive_start(ds)
    # Valid state but Discord returned no code (e.g. user denied) → 400.
    r = await ds.client.get(
        f"/-/discord-auth/callback?state={state}", cookies=cookies
    )
    assert r.status_code == 400
