"""Unit coverage for the Bluesky (AT Protocol OAuth) sample scaffold
(samples/bluesky-auth) — ticket 01. Only the scaffold is exercised here:
discovery, branding, the two `configured()` modes (public URL / dev
loopback), the client-metadata document in both modes, the flow table's
existence after startup, and the 501 stubs for start/callback. Tickets 02-04
add the real PAR/token-exchange coverage.

The module is loaded exactly as ``just dev`` loads it: via Datasette's
``plugins_dir`` (a loose ``.py`` file), NOT an installed distribution.
"""

import json
import re
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pytest
from datasette.app import Datasette

from datasette_accounts import db
from datasette_accounts.providers import get_registry

PAGE_DATA_RE = re.compile(
    r'<script type="application/json" id="pageData">(.*?)</script>', re.S
)


def _extract_page_data(html):
    return json.loads(PAGE_DATA_RE.search(html).group(1))


SAMPLE_DIR = str(Path(__file__).resolve().parent.parent / "samples" / "bluesky-auth")


@pytest.fixture(autouse=True)
def _unregister_sample():
    """Datasette's plugins_dir loader registers ``bluesky_auth.py`` (and, for
    the dev-plugins test, ``load_samples.py``) into the global pluggy manager
    and never removes them, which would leak the bluesky provider into every
    later test's registry (test_providers asserts exact keys). Unregister
    after each test so the loaded sample is scoped here."""
    from datasette.plugins import pm

    yield
    for name in ("bluesky_auth.py", "load_samples.py"):
        if pm.has_plugin(name):
            pm.unregister(name=name)


async def _make_ds():
    ds = Datasette(memory=True, plugins_dir=SAMPLE_DIR)
    await ds.invoke_startup()
    return ds


async def _enable(ds, *, signups=None):
    internal = ds.get_internal_database()
    installed = list(get_registry(ds))
    await db.set_provider_enabled(
        internal, "root", "bluesky", True, installed_keys=installed
    )
    if signups is not None:
        await db.set_provider_signups(internal, "root", "bluesky", signups)


def _configure_public(monkeypatch):
    monkeypatch.setenv("DATASETTE_BLUESKY_PUBLIC_URL", "https://ds.example")
    monkeypatch.delenv("DATASETTE_BLUESKY_DEV_LOOPBACK", raising=False)


def _configure_loopback(monkeypatch):
    monkeypatch.delenv("DATASETTE_BLUESKY_PUBLIC_URL", raising=False)
    monkeypatch.setenv("DATASETTE_BLUESKY_DEV_LOOPBACK", "1")


def _unset_env(monkeypatch):
    monkeypatch.delenv("DATASETTE_BLUESKY_PUBLIC_URL", raising=False)
    monkeypatch.delenv("DATASETTE_BLUESKY_DEV_LOOPBACK", raising=False)


# ==========================================================================
# 1. Discovery + disabled-by-default
# ==========================================================================


@pytest.mark.asyncio
async def test_dev_plugins_loader_serves_every_sample():
    """`just dev` points its single --plugins-dir at samples/dev-plugins,
    whose loader imports every sibling sample — bluesky registers alongside
    discord/github and owns its (disabled -> 404) route surface too. A subset
    assertion (not exact-registry) so a new sample doesn't break this test."""
    dev_plugins = str(
        Path(__file__).resolve().parent.parent / "samples" / "dev-plugins"
    )
    ds = Datasette(memory=True, plugins_dir=dev_plugins)
    await ds.invoke_startup()
    registry = get_registry(ds)
    assert {"discord", "github", "bluesky"} <= set(registry)
    for path in (
        "/-/discord-auth/start",
        "/-/github-auth/start",
        "/-/bluesky-auth/start",
    ):
        r = await ds.client.get(path)
        assert r.status_code == 404, path  # registered route, disabled provider
    # The loader must relay `startup` too, or the flow table never exists
    # under `just dev` (pluggy never sees the sample modules themselves —
    # only the hooks load_samples.py re-exports).
    rows = await ds.get_internal_database().execute(
        "SELECT name FROM sqlite_master WHERE type='table' "
        "AND name='bluesky_auth_oauth_flows'"
    )
    assert [r[0] for r in rows.rows] == ["bluesky_auth_oauth_flows"]


@pytest.mark.asyncio
async def test_bluesky_discovered_via_plugins_dir():
    ds = await _make_ds()
    registry = get_registry(ds)
    assert "bluesky" in registry
    assert registry["bluesky"].label == "Bluesky"
    from datasette_accounts.providers import provider_source

    assert provider_source(registry["bluesky"]) == "bluesky_auth"


@pytest.mark.asyncio
async def test_disabled_by_default_routes_404():
    ds = await _make_ds()  # loaded but never enabled
    for sub in ("start", "callback", "client-metadata.json"):
        r = await ds.client.get(f"/-/bluesky-auth/{sub}")
        assert r.status_code == 404, sub


# ==========================================================================
# 2. Branding: startup validates it, the login page threads it through
# ==========================================================================


@pytest.mark.asyncio
async def test_login_page_hides_unconfigured_bluesky(monkeypatch):
    _unset_env(monkeypatch)
    ds = await _make_ds()  # invoke_startup already ran — validate_branding passed
    await _enable(ds, signups="auto")  # enabled, but no env vars -> unconfigured
    r = await ds.client.get("/-/login")
    data = _extract_page_data(r.text)
    assert "bluesky" not in {p["key"] for p in data["providers"]}


@pytest.mark.asyncio
async def test_login_page_shows_branded_bluesky(monkeypatch):
    _configure_public(monkeypatch)
    ds = await _make_ds()
    await _enable(ds, signups="auto")
    r = await ds.client.get("/-/login")
    data = _extract_page_data(r.text)
    button = {p["key"]: p for p in data["providers"]}.get("bluesky")
    assert button is not None
    # Branding threads from the descriptor: the bi-bluesky SVG mark + brand blue.
    assert button["icon"].startswith("<svg")
    assert 'class="bi bi-bluesky"' in button["icon"]
    assert button["brand_color"] == "#1185FE"


# ==========================================================================
# 3. configured() truth table: public URL / loopback flag / neither
# ==========================================================================


@pytest.mark.asyncio
async def test_configured_public_mode(monkeypatch):
    _configure_public(monkeypatch)
    ds = await _make_ds()
    registry = get_registry(ds)
    assert registry["bluesky"].configured(ds) is True


@pytest.mark.asyncio
async def test_configured_loopback_mode(monkeypatch):
    _configure_loopback(monkeypatch)
    ds = await _make_ds()
    registry = get_registry(ds)
    assert registry["bluesky"].configured(ds) is True


@pytest.mark.asyncio
async def test_configured_neither_mode(monkeypatch):
    _unset_env(monkeypatch)
    ds = await _make_ds()
    registry = get_registry(ds)
    assert registry["bluesky"].configured(ds) is False


# ==========================================================================
# 4. Client-metadata document
# ==========================================================================


@pytest.mark.asyncio
async def test_client_metadata_public_mode(monkeypatch):
    _configure_public(monkeypatch)
    ds = await _make_ds()
    await _enable(ds, signups="auto")
    r = await ds.client.get("/-/bluesky-auth/client-metadata.json")
    assert r.status_code == 200
    data = r.json()
    assert data["client_id"] == "https://ds.example/-/bluesky-auth/client-metadata.json"
    assert data["redirect_uris"] == ["https://ds.example/-/bluesky-auth/callback"]
    assert data["token_endpoint_auth_method"] == "none"
    assert data["dpop_bound_access_tokens"] is True
    assert data["scope"] == "atproto"
    assert data["grant_types"] == ["authorization_code"]
    assert data["response_types"] == ["code"]
    assert data["application_type"] == "web"
    assert data["client_uri"] == "https://ds.example"


@pytest.mark.asyncio
async def test_client_metadata_loopback_mode(monkeypatch):
    _configure_loopback(monkeypatch)
    ds = await _make_ds()
    await _enable(ds, signups="auto")
    r = await ds.client.get("/-/bluesky-auth/client-metadata.json")
    assert r.status_code == 200
    data = r.json()
    assert data["client_id"].startswith("http://localhost?")
    q = parse_qs(urlsplit(data["client_id"]).query)
    assert q["scope"] == ["atproto"]
    redirect_uri = q["redirect_uri"][0]
    assert urlsplit(redirect_uri).hostname == "127.0.0.1"
    assert redirect_uri.endswith("/-/bluesky-auth/callback")
    # The same redirect_uri appears verbatim in redirect_uris.
    assert data["redirect_uris"] == [redirect_uri]
    assert data["token_endpoint_auth_method"] == "none"


# ==========================================================================
# 5. Flow table: created idempotently at startup
# ==========================================================================


@pytest.mark.asyncio
async def test_flow_table_exists_after_startup():
    ds = await _make_ds()
    internal = ds.get_internal_database()
    rows = await internal.execute(
        "SELECT name FROM sqlite_master WHERE type='table' "
        "AND name='bluesky_auth_oauth_flows'"
    )
    assert [r[0] for r in rows.rows] == ["bluesky_auth_oauth_flows"]

    # Idempotent: invoking startup again (e.g. a second import in the same
    # process) must not raise.
    await ds.invoke_startup()


# ==========================================================================
# 6. start/callback stubs: 501 once enabled
# ==========================================================================


@pytest.mark.asyncio
async def test_start_stub_returns_501(monkeypatch):
    _configure_public(monkeypatch)
    ds = await _make_ds()
    await _enable(ds, signups="auto")
    r = await ds.client.get("/-/bluesky-auth/start")
    assert r.status_code == 501


@pytest.mark.asyncio
async def test_callback_stub_returns_501(monkeypatch):
    _configure_public(monkeypatch)
    ds = await _make_ds()
    await _enable(ds, signups="auto")
    r = await ds.client.get("/-/bluesky-auth/callback")
    assert r.status_code == 501
