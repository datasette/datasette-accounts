"""Unit coverage for the Bluesky (AT Protocol OAuth) sample scaffold
(samples/bluesky-auth) — ticket 01. Only the scaffold is exercised here:
discovery, branding, the two `configured()` modes (public URL / dev
loopback), the client-metadata document in both modes, the flow table's
existence after startup, and the 501 stubs for start/callback. Tickets 02-04
add the real PAR/token-exchange coverage.

The module is loaded exactly as ``just dev`` loads it: via Datasette's
``plugins_dir`` (a loose ``.py`` file), NOT an installed distribution.
"""

import base64
import hashlib
import importlib.util
import json
import re
from pathlib import Path
from urllib.parse import parse_qs, quote, urlsplit

import pytest
from authlib.jose import JsonWebKey, jwt
from datasette.app import Datasette

from datasette_accounts import db
from datasette_accounts.providers import get_registry

PAGE_DATA_RE = re.compile(
    r'<script type="application/json" id="pageData">(.*?)</script>', re.S
)


def _extract_page_data(html):
    return json.loads(PAGE_DATA_RE.search(html).group(1))


SAMPLE_DIR = str(Path(__file__).resolve().parent.parent / "samples" / "bluesky-auth")


def _load_bluesky_module():
    """Load the sample as a plain module (ticket 02's protocol helpers are
    pure — no Datasette instance needed). This is exactly how
    ``samples/dev-plugins/load_samples.py`` imports it, and registers nothing
    with pluggy, so the autouse unregister fixture is unaffected."""
    spec = importlib.util.spec_from_file_location(
        "bluesky_auth", str(Path(SAMPLE_DIR) / "bluesky_auth.py")
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


bluesky_auth = _load_bluesky_module()


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


# ==========================================================================
# 7. Protocol helpers (ticket 02): DPoP + PKCE + identity resolution
#
# Pure-helper coverage — the module is imported directly (bluesky_auth above),
# no Datasette instance. httpx-using helpers take the client as a parameter,
# so these fakes stand in for it.
# ==========================================================================


class _FakeResp:
    def __init__(self, status_code=200, json_data=None, headers=None):
        self.status_code = status_code
        self._json = json_data
        self.headers = headers or {}

    def json(self):
        if self._json is None:
            raise ValueError("no JSON body")
        return self._json


class _FakeGetClient:
    """Routes GET by exact URL (params ignored — they don't change the route
    the helpers hit). Any unrouted URL is a test bug, not a 404 path."""

    def __init__(self, routes):
        self.routes = routes
        self.get_calls = []

    async def get(self, url, params=None):
        self.get_calls.append((url, params))
        if url not in self.routes:
            raise AssertionError(f"unexpected GET {url!r}")
        return self.routes[url]


class _FakePostClient:
    def __init__(self, responses):
        self._responses = list(responses)
        self.posts = []

    async def post(self, url, data=None, headers=None):
        self.posts.append({"url": url, "data": data, "headers": headers})
        return self._responses.pop(0)


def test_dpop_proof_shape_and_no_private_scalar():
    jwk = bluesky_auth._gen_dpop_jwk()
    key = JsonWebKey.import_key(jwk)

    proof = bluesky_auth._dpop_proof(jwk, "POST", "https://pds.example/par?foo=bar")
    # Verifies against the (public) key embedded in the header.
    claims = jwt.decode(proof, key)
    header = claims.header

    assert header["typ"] == "dpop+jwt"
    assert header["alg"] == "ES256"
    # CRITICAL invariant: the header jwk is the public half only — the private
    # scalar `d` must never ride along.
    assert "d" not in header["jwk"]

    assert claims["htm"] == "POST"
    assert claims["htu"] == "https://pds.example/par"  # query stripped
    assert claims["jti"]
    assert isinstance(claims["iat"], int)
    assert "nonce" not in claims

    # nonce present iff passed.
    with_nonce = jwt.decode(
        bluesky_auth._dpop_proof(jwk, "POST", "https://x/y", nonce="n-9"), key
    )
    assert with_nonce["nonce"] == "n-9"

    # Fresh jti per proof.
    a = jwt.decode(bluesky_auth._dpop_proof(jwk, "POST", "https://x/y"), key)
    b = jwt.decode(bluesky_auth._dpop_proof(jwk, "POST", "https://x/y"), key)
    assert a["jti"] != b["jti"]


def test_pkce_pair():
    verifier, challenge = bluesky_auth._pkce_pair()
    expected = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
        .rstrip(b"=")
        .decode()
    )
    assert challenge == expected
    assert 43 <= len(verifier) <= 128  # RFC 7636


@pytest.mark.asyncio
async def test_post_with_dpop_retries_on_use_dpop_nonce():
    jwk = bluesky_auth._gen_dpop_jwk()
    key = JsonWebKey.import_key(jwk)
    resp1 = _FakeResp(400, {"error": "use_dpop_nonce"}, {"DPoP-Nonce": "n-1"})
    resp2 = _FakeResp(200, {"request_uri": "urn:x"}, {"DPoP-Nonce": "n-2"})
    client = _FakePostClient([resp1, resp2])

    resp, latest = await bluesky_auth._post_with_dpop(
        client, jwk, "https://as.example/par", {"a": "b"}
    )

    assert len(client.posts) == 2  # retried exactly once
    assert resp is resp2
    assert latest == "n-2"  # freshest DPoP-Nonce, read off the 200 too
    # The retry folded the server nonce into the second proof; the first had none.
    first = jwt.decode(client.posts[0]["headers"]["DPoP"], key)
    second = jwt.decode(client.posts[1]["headers"]["DPoP"], key)
    assert "nonce" not in first
    assert second["nonce"] == "n-1"


@pytest.mark.asyncio
async def test_post_with_dpop_other_4xx_does_not_retry():
    jwk = bluesky_auth._gen_dpop_jwk()
    resp1 = _FakeResp(400, {"error": "invalid_request"}, {"DPoP-Nonce": "n-1"})
    client = _FakePostClient([resp1])  # only one — a retry would IndexError

    resp, latest = await bluesky_auth._post_with_dpop(
        client, jwk, "https://as.example/par", {}
    )

    assert len(client.posts) == 1
    assert resp is resp1
    assert latest == "n-1"


@pytest.mark.asyncio
async def test_resolve_handle():
    client = _FakeGetClient(
        {bluesky_auth.RESOLVE_HANDLE_URL: _FakeResp(200, {"did": "did:plc:abc"})}
    )
    assert await bluesky_auth._resolve_handle(client, "alice.test") == "did:plc:abc"


@pytest.mark.asyncio
async def test_did_plc_doc_pds_and_handle():
    did = "did:plc:abc123"
    plc_url = f"https://plc.directory/{quote(did, safe='')}"
    doc = {
        "alsoKnownAs": ["at://alice.test"],
        "service": [
            {
                "id": "#atproto_pds",
                "type": "AtprotoPersonalDataServer",
                "serviceEndpoint": "https://pds.example",
            }
        ],
    }
    client = _FakeGetClient({plc_url: _FakeResp(200, doc)})

    got = await bluesky_auth._did_doc(client, did)
    assert got == doc
    assert bluesky_auth._pds_endpoint(got) == "https://pds.example"
    assert bluesky_auth._handle_from_did_doc(got) == "alice.test"


@pytest.mark.asyncio
async def test_did_web_doc_uses_well_known():
    did = "did:web:example.com"
    url = "https://example.com/.well-known/did.json"
    doc = {"service": []}
    client = _FakeGetClient({url: _FakeResp(200, doc)})

    assert await bluesky_auth._did_doc(client, did) == doc
    assert client.get_calls[0][0] == url


@pytest.mark.asyncio
async def test_did_doc_rejects_unknown_method_and_web_path_form():
    with pytest.raises(bluesky_auth.FlowError):
        await bluesky_auth._did_doc(_FakeGetClient({}), "did:key:z6Mk")
    with pytest.raises(bluesky_auth.FlowError):
        await bluesky_auth._did_doc(
            _FakeGetClient({}), "did:web:example.com:user:alice"
        )


def test_pds_endpoint_requires_service_and_https():
    with pytest.raises(bluesky_auth.FlowError):
        bluesky_auth._pds_endpoint(
            {"service": [{"id": "#other", "serviceEndpoint": "https://x"}]}
        )
    with pytest.raises(bluesky_auth.FlowError):
        bluesky_auth._pds_endpoint(
            {
                "service": [
                    {"id": "#atproto_pds", "serviceEndpoint": "http://pds.example"}
                ]
            }
        )


@pytest.mark.asyncio
async def test_resolve_authserver():
    pds = "https://pds.example"
    url = pds + "/.well-known/oauth-protected-resource"
    client = _FakeGetClient(
        {url: _FakeResp(200, {"authorization_servers": ["https://as.example"]})}
    )
    assert await bluesky_auth._resolve_authserver(client, pds) == "https://as.example"


@pytest.mark.asyncio
async def test_authserver_metadata_ok_and_issuer_mismatch():
    issuer = "https://as.example"
    url = issuer + "/.well-known/oauth-authorization-server"
    meta = {
        "issuer": issuer,
        "pushed_authorization_request_endpoint": "https://as.example/par",
        "authorization_endpoint": "https://as.example/authorize",
        "token_endpoint": "https://as.example/token",
    }
    client = _FakeGetClient({url: _FakeResp(200, meta)})
    assert await bluesky_auth._authserver_metadata(client, issuer) == meta

    bad = dict(meta, issuer="https://evil.example")
    client2 = _FakeGetClient({url: _FakeResp(200, bad)})
    with pytest.raises(bluesky_auth.FlowError):
        await bluesky_auth._authserver_metadata(client2, issuer)
