"""Unit coverage for the GitHub OAuth2 sample (samples/github-auth).

A mirror of test_discord_sample.py for the second real-OAuth2 sample: the
callback exchanges a code for a token and reads the GitHub user over HTTP, so
``httpx.AsyncClient`` is monkeypatched (module-locally) with a tiny fake that
returns canned token + user responses — the provider's own HTTP calls never
leave the process. The GitHub-specific behaviours covered on top of the shared
shape: no ``scope`` on the authorize URL, ``Accept: application/json`` on the
token exchange, and the token endpoint's errors-as-HTTP-200 quirk.

The module is loaded exactly as ``just dev`` loads it: via Datasette's
``plugins_dir`` (a loose ``.py`` file), NOT an installed distribution.
"""

import json
import re
import types
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import pytest
from datasette.app import Datasette

from datasette_accounts import db
from datasette_accounts.providers import STATE_COOKIE, get_registry
from datasette_accounts.security import COOKIE_NAME

JSON = {"content-type": "application/json"}

PAGE_DATA_RE = re.compile(
    r'<script type="application/json" id="pageData">(.*?)</script>', re.S
)


def _extract_page_data(html):
    return json.loads(PAGE_DATA_RE.search(html).group(1))


SAMPLE_DIR = str(Path(__file__).resolve().parent.parent / "samples" / "github-auth")

# Canned GitHub /user response. `id` is an int in the real API — the provider
# must stringify it for the identity subject. Logins can be renamed; ids can't.
GITHUB_ME = {
    "id": 583231,
    "login": "octocat",
    "name": "The Octocat",
    "email": None,
}


class _FakeResponse:
    def __init__(self, data):
        self._data = data

    def json(self):
        return self._data

    def raise_for_status(self):
        return None


def _fake_async_client(token_payload):
    """Build a fake httpx.AsyncClient class whose post() answers the token
    exchange with `token_payload` and whose get() answers /user. Calls are
    recorded on the module-level `calls` dict for assertions."""
    calls = {"posts": [], "gets": []}

    class _FakeAsyncClient:
        def __init__(self, *args, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return False

        async def post(self, url, data=None, headers=None, **kwargs):
            calls["posts"].append((url, data, headers))
            return _FakeResponse(token_payload)

        async def get(self, url, headers=None, **kwargs):
            calls["gets"].append((url, headers))
            return _FakeResponse(GITHUB_ME)

    return _FakeAsyncClient, calls


@pytest.fixture(autouse=True)
def _unregister_sample():
    """Datasette's plugins_dir loader registers ``github_auth.py`` (and, for the
    dev-plugins test, ``load_samples.py``) into the global pluggy manager and
    never removes them, which would leak the github provider into every later
    test's registry (test_providers asserts exact keys). Unregister after each
    test so the loaded sample is scoped here."""
    from datasette.plugins import pm

    yield
    for name in ("github_auth.py", "load_samples.py"):
        if pm.has_plugin(name):
            pm.unregister(name=name)


async def _make_ds():
    ds = Datasette(memory=True, plugins_dir=SAMPLE_DIR)
    await ds.invoke_startup()
    return ds


def _mock_httpx(monkeypatch, token_payload=None):
    """Swap ONLY the github_auth module's ``httpx`` reference for a shim exposing
    the fake AsyncClient (patching the global would break Datasette's own
    httpx-based test client) — same targeting as the Discord test: through the
    gated handler's ``__wrapped__.__globals__``."""
    from datasette.plugins import pm

    if token_payload is None:
        token_payload = {"access_token": "fake-access-token", "token_type": "bearer"}
    fake_client, calls = _fake_async_client(token_payload)
    module = pm.get_plugin("github_auth.py")  # the loose plugins_dir module
    module_globals = module.callback.__wrapped__.__globals__
    monkeypatch.setitem(
        module_globals, "httpx", types.SimpleNamespace(AsyncClient=fake_client)
    )
    return calls


async def _enable(ds, *, signups=None):
    internal = ds.get_internal_database()
    installed = list(get_registry(ds))
    await db.set_provider_enabled(
        internal, "root", "github", True, installed_keys=installed
    )
    if signups is not None:
        await db.set_provider_signups(internal, "root", "github", signups)


def _configure_env(monkeypatch):
    monkeypatch.setenv("DATASETTE_GITHUB_CLIENT_ID", "client-abc")
    monkeypatch.setenv("DATASETTE_GITHUB_CLIENT_SECRET", "secret-xyz")


def _unset_env(monkeypatch):
    monkeypatch.delenv("DATASETTE_GITHUB_CLIENT_ID", raising=False)
    monkeypatch.delenv("DATASETTE_GITHUB_CLIENT_SECRET", raising=False)


# ==========================================================================
# 1. Discovery + disabled-by-default
# ==========================================================================


@pytest.mark.asyncio
async def test_dev_plugins_loader_serves_every_sample():
    """`just dev` points its single --plugins-dir at samples/dev-plugins, whose
    loader imports every sibling sample — both providers register and both own
    their (disabled → 404) route surfaces."""
    dev_plugins = str(
        Path(__file__).resolve().parent.parent / "samples" / "dev-plugins"
    )
    ds = Datasette(memory=True, plugins_dir=dev_plugins)
    await ds.invoke_startup()
    registry = get_registry(ds)
    assert {"discord", "github"} <= set(registry)
    for path in ("/-/discord-auth/start", "/-/github-auth/start"):
        r = await ds.client.get(path)
        assert r.status_code == 404, path  # registered route, disabled provider


@pytest.mark.asyncio
async def test_github_discovered_via_plugins_dir():
    ds = await _make_ds()
    registry = get_registry(ds)
    assert "github" in registry
    assert registry["github"].label == "GitHub"
    from datasette_accounts.providers import provider_source

    assert provider_source(registry["github"]) == "github_auth"


@pytest.mark.asyncio
async def test_disabled_by_default_routes_404():
    ds = await _make_ds()  # loaded but never enabled
    for sub in ("start", "callback"):
        r = await ds.client.get(f"/-/github-auth/{sub}")
        assert r.status_code == 404, sub


# ==========================================================================
# 2. start — unconfigured 503, configured 302 to github.com
# ==========================================================================


@pytest.mark.asyncio
async def test_start_unconfigured_returns_503(monkeypatch):
    _unset_env(monkeypatch)
    ds = await _make_ds()
    await _enable(ds, signups="auto")
    r = await ds.client.get("/-/github-auth/start")
    assert r.status_code == 503
    assert "not configured" in r.text


@pytest.mark.asyncio
async def test_start_configured_redirects_to_github(monkeypatch):
    _configure_env(monkeypatch)
    ds = await _make_ds()
    await _enable(ds, signups="auto")

    r = await ds.client.get("/-/github-auth/start?next=/-/account")
    assert r.status_code == 302
    location = r.headers["location"]
    assert location.startswith("https://github.com/login/oauth/authorize?")
    q = parse_qs(urlparse(location).query)
    assert q["client_id"] == ["client-abc"]
    assert q["redirect_uri"][0].endswith("/-/github-auth/callback")
    # No scope requested: the empty default grants public read-only access,
    # which is all /user needs.
    assert "scope" not in q
    # The state is core-minted: it round-trips through the state cookie.
    state_cookie = r.cookies.get(STATE_COOKIE)
    assert state_cookie
    assert q["state"][0]  # present + non-empty


# ==========================================================================
# 3. callback — mocked token + user responses provision an account (auto)
# ==========================================================================


async def _drive_start(ds):
    """Drive start → return (state_value, cookies) for a callback."""
    r = await ds.client.get("/-/github-auth/start")
    assert r.status_code == 302
    state = parse_qs(urlparse(r.headers["location"]).query)["state"][0]
    return state, {STATE_COOKIE: r.cookies.get(STATE_COOKIE)}


@pytest.mark.asyncio
async def test_callback_auto_provisions_and_mints(monkeypatch):
    _configure_env(monkeypatch)
    ds = await _make_ds()
    calls = _mock_httpx(monkeypatch)
    await _enable(ds, signups="auto")
    internal = ds.get_internal_database()

    state, cookies = await _drive_start(ds)
    r = await ds.client.get(
        f"/-/github-auth/callback?state={state}&code=oauth-code",
        cookies=cookies,
    )
    assert r.status_code == 302
    session = r.cookies.get(COOKIE_NAME)
    assert session  # a real session was minted on the github provenance

    # The token exchange asked GitHub for JSON (else it answers form-encoded).
    (token_url, token_data, token_headers) = calls["posts"][0]
    assert token_url == "https://github.com/login/oauth/access_token"
    assert token_headers["Accept"] == "application/json"
    assert token_data["code"] == "oauth-code"

    # The identity was keyed on the stringified numeric id (never login/email).
    ident = await db.get_identity(internal, "github", str(GITHUB_ME["id"]))
    assert ident is not None
    user = await db.get_user_by_id(internal, ident["user_id"])
    assert user["username"] == "octocat"  # derived from username_hint
    assert user["pending_approval"] == 0

    srows = await internal.execute(f"SELECT provider FROM {db.SESSIONS}")
    assert [row[0] for row in srows.rows] == ["github"]
    last = await internal.execute(
        f"SELECT reason, provider FROM {db.LOGIN_AUDIT} ORDER BY id DESC LIMIT 1"
    )
    assert dict(last.rows[0]) == {"reason": "success", "provider": "github"}


@pytest.mark.asyncio
async def test_callback_without_state_fails(monkeypatch):
    _configure_env(monkeypatch)
    ds = await _make_ds()
    _mock_httpx(monkeypatch)
    await _enable(ds, signups="auto")
    # No state cookie / query arg → read_state guard trips before any HTTP call.
    r = await ds.client.get("/-/github-auth/callback?code=x")
    assert r.status_code == 400


@pytest.mark.asyncio
async def test_callback_without_code_fails(monkeypatch):
    _configure_env(monkeypatch)
    ds = await _make_ds()
    _mock_httpx(monkeypatch)
    await _enable(ds, signups="auto")
    state, cookies = await _drive_start(ds)
    # Valid state but GitHub returned no code (e.g. user denied) → 400.
    r = await ds.client.get(f"/-/github-auth/callback?state={state}", cookies=cookies)
    assert r.status_code == 400


@pytest.mark.asyncio
async def test_callback_token_error_as_http_200_fails(monkeypatch):
    """GitHub's token endpoint reports errors (bad/expired code, mismatched
    redirect_uri) as HTTP 200 with an {"error": ...} body — the callback must
    gate on access_token presence, not raise_for_status."""
    _configure_env(monkeypatch)
    ds = await _make_ds()
    calls = _mock_httpx(
        monkeypatch,
        token_payload={"error": "bad_verification_code"},
    )
    await _enable(ds, signups="auto")
    internal = ds.get_internal_database()

    state, cookies = await _drive_start(ds)
    r = await ds.client.get(
        f"/-/github-auth/callback?state={state}&code=expired-code",
        cookies=cookies,
    )
    assert r.status_code == 400
    assert calls["gets"] == []  # never reached /user
    # Nothing was provisioned or minted.
    urows = await internal.execute(f"SELECT COUNT(*) FROM {db.USERS}")
    assert urows.rows[0][0] == 0
    srows = await internal.execute(f"SELECT COUNT(*) FROM {db.SESSIONS}")
    assert srows.rows[0][0] == 0


# ==========================================================================
# 4. configured dimension + login-page branding
# ==========================================================================


@pytest.mark.asyncio
async def test_login_page_hides_unconfigured_github(monkeypatch):
    _unset_env(monkeypatch)
    ds = await _make_ds()
    await _enable(ds, signups="auto")  # enabled, but env vars absent
    r = await ds.client.get("/-/login")
    data = _extract_page_data(r.text)
    assert "github" not in {p["key"] for p in data["providers"]}


@pytest.mark.asyncio
async def test_login_page_shows_branded_github(monkeypatch):
    _configure_env(monkeypatch)
    ds = await _make_ds()
    await _enable(ds, signups="auto")
    r = await ds.client.get("/-/login")
    data = _extract_page_data(r.text)
    button = {p["key"]: p for p in data["providers"]}.get("github")
    assert button is not None
    # Branding threads from the descriptor: the bi-github SVG mark + near-black.
    assert button["icon"].startswith("<svg")
    assert 'class="bi bi-github"' in button["icon"]
    assert button["brand_color"] == "#24292F"
