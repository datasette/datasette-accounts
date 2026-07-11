"""Page-data coverage for the provider frontends (ticket 06).

Asserts the server-rendered `#pageData` that the login / account / config Svelte
pages consume: login provider buttons (with `next` threading), the password-
disabled buttons-only state, the Configuration providers rows, and the account
page's identities + linkable-provider shape + session provenance.

Self-contained (its own provider fixture + helpers) so it never imports the
other provider test modules — several of which are edited in parallel.
"""

import json
import re
import types
from urllib.parse import quote

import pytest
from datasette import hookimpl
from datasette.app import Datasette
from datasette.plugins import pm

from datasette_accounts import db
from datasette_accounts.passwords import UNUSABLE_PASSWORD, hash_password
from datasette_accounts.providers import AuthProvider, ExternalIdentity
from datasette_accounts.security import COOKIE_NAME, SIGN_NAMESPACE
from datasette_accounts.sessions import mint_token, token_sha256

JSON = {"content-type": "application/json"}

PAGE_DATA_RE = re.compile(
    r'<script type="application/json" id="pageData">(.*?)</script>', re.S
)


def extract_page_data(html):
    return json.loads(PAGE_DATA_RE.search(html).group(1))


class DummyProvider(AuthProvider):
    def __init__(self, key, label):
        self.key = key
        self.label = label
        # Own-routes descriptor (D3b): the login button reads start_path. This
        # page-data test never drives a flow, so no routes are registered.
        self.start_path = f"/-/{key}-auth/start"


class UnconfiguredProvider(DummyProvider):
    """An enabled-but-not-deployed provider: `configured()` reports False, so
    every user-facing surface hides it while the admin table still lists it."""

    def configured(self, datasette):
        return False


class RaisingProvider(DummyProvider):
    """A misbehaving provider whose `configured()` raises — must be treated as
    NOT configured (defensively) and never 500 a page render."""

    def configured(self, datasette):
        raise RuntimeError("boom")


@pytest.fixture
def register_providers():
    names = []

    def _register(providers):
        name = f"pagedata-providers-{len(names)}"
        mod = types.ModuleType(name)

        @hookimpl
        def datasette_accounts_auth_providers(datasette):
            return list(providers)

        mod.datasette_accounts_auth_providers = datasette_accounts_auth_providers
        pm.register(mod, name=name)
        names.append(name)

    yield _register
    for name in names:
        if pm.get_plugin(name) is not None:
            pm.unregister(name=name)


async def make_ds(**plugin_config):
    metadata = {}
    if plugin_config:
        metadata = {"plugins": {"datasette-accounts": plugin_config}}
    ds = Datasette(memory=True, metadata=metadata)
    await ds.invoke_startup()
    return ds


async def _set_setting(ds, key, value):
    internal = ds.get_internal_database()
    await internal.execute_write(
        f"INSERT OR REPLACE INTO {db.SETTINGS} (key, value, updated_at) "
        "VALUES (?, ?, ?)",
        [key, value, db.now_iso()],
    )


async def _enable(ds, key):
    await _set_setting(ds, f"provider:{key}:enabled", "1")


async def _insert_user(ds, username, *, is_admin=False, password_less=False):
    internal = ds.get_internal_database()
    uid = db.new_id()
    ts = db.now_iso()
    pw = UNUSABLE_PASSWORD if password_less else hash_password("password123")
    await internal.execute_write(
        f"INSERT INTO {db.USERS} (id, username, password_hash, is_admin, disabled, "
        "must_change_password, failed_attempts, locked_until, created_at, updated_at, "
        "expires_at, pending_approval) "
        "VALUES (?, ?, ?, ?, 0, 0, 0, NULL, ?, ?, NULL, 0)",
        [uid, username, pw, 1 if is_admin else 0, ts, ts],
    )
    return uid


async def _session_cookie(ds, uid):
    internal = ds.get_internal_database()
    raw = mint_token()
    await db.create_session(internal, uid, token_sha256(raw), 14, "ua", "1.1.1.1")
    return ds.sign(raw, SIGN_NAMESPACE)


async def _link(ds, uid, provider, subject):
    internal = ds.get_internal_database()
    await db.link_identity(
        internal, uid, uid, ExternalIdentity(provider=provider, subject=subject)
    )


# --------------------------------------------------------------------------
# Login page
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_login_page_provider_buttons_thread_next(register_providers):
    register_providers([DummyProvider("acme", "Acme"), DummyProvider("okta", "Okta")])
    ds = await make_ds()
    # Only enable one of the two external providers.
    await _enable(ds, "acme")

    r = await ds.client.get("/-/login?next=/reports")
    data = extract_page_data(r.text)

    assert data["password_enabled"] is True
    # Only the ENABLED external provider renders a button.
    assert [p["key"] for p in data["providers"]] == ["acme"]
    button = data["providers"][0]
    assert button["label"] == "Acme"
    # The validated `next` is threaded into the redirect-based start_url.
    assert button["start_url"] == ("/-/acme-auth/start?next=" + quote("/reports"))


@pytest.mark.asyncio
async def test_login_page_password_disabled_buttons_only(register_providers):
    register_providers([DummyProvider("okta", "Okta")])
    ds = await make_ds()
    await _enable(ds, "okta")
    # SSO-only instance: an admin disabled the built-in password provider.
    await _set_setting(ds, "provider:password:enabled", "0")

    r = await ds.client.get("/-/login")
    data = extract_page_data(r.text)

    assert data["password_enabled"] is False
    assert [p["key"] for p in data["providers"]] == ["okta"]
    assert data["providers"][0]["start_url"].startswith("/-/okta-auth/start?next=")


@pytest.mark.asyncio
async def test_login_page_no_external_providers(register_providers):
    register_providers([])
    ds = await make_ds()
    r = await ds.client.get("/-/login")
    data = extract_page_data(r.text)
    assert data["password_enabled"] is True
    assert data["providers"] == []


@pytest.mark.asyncio
async def test_login_page_hides_enabled_but_unconfigured(register_providers):
    # Two enabled external providers, but one reports configured()=False (its
    # credentials aren't deployed). Only the configured one gets a button.
    register_providers(
        [DummyProvider("acme", "Acme"), UnconfiguredProvider("okta", "Okta")]
    )
    ds = await make_ds()
    await _enable(ds, "acme")
    await _enable(ds, "okta")

    r = await ds.client.get("/-/login")
    data = extract_page_data(r.text)
    assert [p["key"] for p in data["providers"]] == ["acme"]


@pytest.mark.asyncio
async def test_login_page_renders_when_configured_raises(register_providers):
    # A provider whose configured() raises must be treated as unconfigured and
    # must never break the page render (defensive provider_configured guard).
    register_providers([RaisingProvider("acme", "Acme")])
    ds = await make_ds()
    await _enable(ds, "acme")

    r = await ds.client.get("/-/login")
    assert r.status_code == 200
    data = extract_page_data(r.text)
    assert data["providers"] == []


# --------------------------------------------------------------------------
# Configuration page
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_config_page_provider_rows(register_providers):
    register_providers([DummyProvider("acme", "Acme")])
    ds = await make_ds()
    await _enable(ds, "acme")
    await _set_setting(ds, "provider:acme:signups", "auto")
    uid = await _insert_user(ds, "admin", is_admin=True)
    sess = await _session_cookie(ds, uid)

    r = await ds.client.get("/-/admin/config", cookies={COOKIE_NAME: sess})
    data = extract_page_data(r.text)

    rows = {p["key"]: p for p in data["providers"]}
    # The installed datasette-accounts-demo-auth example package also lists a
    # `demo` provider (disabled by default) on every instance — assert our two
    # are present rather than exact equality.
    assert {"password", "acme"} <= set(rows)
    # Built-in password provider: enabled by default, source is our package.
    pw = rows["password"]
    assert pw["builtin"] is True
    assert pw["enabled"] is True
    assert pw["source"] == "datasette_accounts"
    assert pw["linked_count"] == 0
    # External provider: enabled + signups reflect the settings rows.
    acme = rows["acme"]
    assert acme["builtin"] is False
    assert acme["enabled"] is True
    assert acme["signups"] == "auto"
    assert acme["label"] == "Acme"
    # A provider that needs no external config reports configured=True (default);
    # the built-in password provider does too.
    assert acme["configured"] is True
    assert pw["configured"] is True


@pytest.mark.asyncio
async def test_config_page_shows_enabled_but_unconfigured(register_providers):
    # Admins must see reality: an enabled-but-unconfigured provider still lists,
    # with enabled=True AND configured=False (the frontend flags it).
    register_providers([UnconfiguredProvider("okta", "Okta")])
    ds = await make_ds()
    await _enable(ds, "okta")
    uid = await _insert_user(ds, "admin", is_admin=True)
    sess = await _session_cookie(ds, uid)

    r = await ds.client.get("/-/admin/config", cookies={COOKIE_NAME: sess})
    data = extract_page_data(r.text)
    rows = {p["key"]: p for p in data["providers"]}
    assert rows["okta"]["enabled"] is True
    assert rows["okta"]["configured"] is False


# --------------------------------------------------------------------------
# Account page
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_account_page_identities_and_linkable(register_providers):
    register_providers([DummyProvider("acme", "Acme"), DummyProvider("okta", "Okta")])
    ds = await make_ds()
    await _enable(ds, "acme")
    await _enable(ds, "okta")
    uid = await _insert_user(ds, "alice")
    await _link(ds, uid, "acme", "acme-123")
    sess = await _session_cookie(ds, uid)

    r = await ds.client.get("/-/account", cookies={COOKIE_NAME: sess})
    data = extract_page_data(r.text)

    assert data["has_password"] is True
    # The linked identity carries its resolved label + subject.
    assert [(i["provider"], i["label"], i["subject"]) for i in data["identities"]] == [
        ("acme", "Acme", "acme-123")
    ]
    # linkable_providers is a list of {key, label} objects: the enabled external
    # providers NOT already linked (okta), never the already-linked acme.
    assert data["linkable_providers"] == [{"key": "okta", "label": "Okta"}]
    # Session provenance: the mint stamped 'password' on this session row.
    assert data["sessions"]
    assert data["sessions"][0]["provider"] == "password"


@pytest.mark.asyncio
async def test_account_page_linkable_omits_unconfigured(register_providers):
    # An enabled-but-unconfigured provider can't complete a link flow, so it is
    # filtered out of the account page's linkable list exactly like the login
    # button — only the configured `acme` is offered.
    register_providers(
        [DummyProvider("acme", "Acme"), UnconfiguredProvider("okta", "Okta")]
    )
    ds = await make_ds()
    await _enable(ds, "acme")
    await _enable(ds, "okta")
    uid = await _insert_user(ds, "alice")
    sess = await _session_cookie(ds, uid)

    r = await ds.client.get("/-/account", cookies={COOKIE_NAME: sess})
    data = extract_page_data(r.text)
    assert [p["key"] for p in data["linkable_providers"]] == ["acme"]


@pytest.mark.asyncio
async def test_account_page_password_less_linkable_shape(register_providers):
    register_providers([DummyProvider("acme", "Acme")])
    ds = await make_ds()
    await _enable(ds, "acme")
    uid = await _insert_user(ds, "sso-only", password_less=True)
    await _link(ds, uid, "acme", "acme-9")
    sess = await _session_cookie(ds, uid)

    r = await ds.client.get("/-/account", cookies={COOKIE_NAME: sess})
    data = extract_page_data(r.text)

    assert data["has_password"] is False
    assert [i["subject"] for i in data["identities"]] == ["acme-9"]
    # acme is linked and is the only external provider → nothing left to link.
    assert data["linkable_providers"] == []
