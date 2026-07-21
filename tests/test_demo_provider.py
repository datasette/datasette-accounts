"""End-to-end coverage driven through the INSTALLED demo provider package.

Ticket plans/auth2/tickets/core-07-demo-docs.md. Unlike the other provider
tests — which register a throwaway provider through pluggy — this file drives
``examples/datasette-accounts-demo-auth`` as a real entry-point-installed
distribution (`[project.entry-points.datasette]`). That is the whole point: it
proves the ``datasette_accounts_auth_providers`` hookspec works for an
out-of-tree package discovered the same way any pip-installed plugin is.

The demo provider's own routes run the exact start → external redirect → IdP
page → callback → ``read_state`` → ``ExternalIdentity`` → ``finish_login``
sequence a real OAuth provider uses, so exercising it exercises the full
external path. Nothing here imports the demo package's module — discovery is via
the installed entry point alone.
"""

from urllib.parse import parse_qs, urlparse

import pytest
from datasette.app import Datasette

from datasette_accounts import db
from datasette_accounts.passwords import UNUSABLE_PASSWORD, hash_password
from datasette_accounts.providers import (
    ExternalIdentity,
    get_registry,
)
from datasette_accounts.security import COOKIE_NAME, SIGN_NAMESPACE
from datasette_accounts.sessions import mint_token, token_sha256

# The state cookie name is a provider-facing constant; import it rather than
# hard-coding so this test tracks any rename.
from datasette_accounts.providers import STATE_COOKIE

JSON = {"content-type": "application/json"}


async def make_ds(**plugin_config):
    metadata = {}
    if plugin_config:
        metadata = {"plugins": {"datasette-accounts": plugin_config}}
    ds = Datasette(memory=True, metadata=metadata)
    await ds.invoke_startup()
    return ds


async def _enable(ds, key, *, signups=None):
    """Enable a provider + optionally set its signups mode via the real ticket-05
    db functions (audited, guarded), exactly as the admin UI / CLI would."""
    internal = ds.get_internal_database()
    installed = list(get_registry(ds))
    await db.set_provider_enabled(internal, "root", key, True, installed_keys=installed)
    if signups is not None:
        await db.set_provider_signups(internal, "root", key, signups)


async def insert_user(ds, username, *, password="password123", password_less=False):
    internal = ds.get_internal_database()
    uid = db.new_id()
    ts = db.now_iso()
    pw = UNUSABLE_PASSWORD if password_less else hash_password(password)
    await internal.execute_write(
        f"INSERT INTO {db.USERS} (id, username, password_hash, is_admin, disabled, "
        "must_change_password, failed_attempts, locked_until, created_at, updated_at, "
        "expires_at, pending_approval) "
        "VALUES (?, ?, ?, 0, 0, 0, 0, NULL, ?, ?, NULL, 0)",
        [uid, username, pw, ts, ts],
    )
    return uid


async def _session_cookie(ds, uid):
    internal = ds.get_internal_database()
    raw = mint_token()
    await db.create_session(internal, uid, token_sha256(raw), 14, "ua", "1.1.1.1")
    return ds.sign(raw, SIGN_NAMESPACE)


def _state_value(location):
    """Pull the `state` query value out of a redirect Location."""
    return parse_qs(urlparse(location).query)["state"][0]


async def _drive_login(
    ds, subject, *, pin="1234", username=None, name=None, session=None
):
    """Drive a fresh login through the demo provider: start → idp → callback.

    Returns the final callback Response. Carries the state cookie start sets, and
    (for link flows) an existing session cookie. Asserts the pretend-IdP page
    renders its loud dev-only banner along the way. The first sign-in with a
    subject claims it with `pin`; later drives must present the same PIN.
    """
    cookies = {}
    if session:
        cookies[COOKIE_NAME] = session

    # 1. start → 302 to the pretend IdP, carrying the state, setting the cookie.
    r1 = await ds.client.get("/-/demo-auth/start", cookies=cookies)
    assert r1.status_code == 302
    idp_url = r1.headers["location"]
    assert idp_url.startswith("/-/demo-auth/idp?state=")
    state_cookie = r1.cookies.get(STATE_COOKIE)
    assert state_cookie
    cookies[STATE_COOKIE] = state_cookie
    state = _state_value(idp_url)

    # 2. the pretend IdP page: loud dev-only banner + a PIN form back to callback.
    r2 = await ds.client.get(idp_url, cookies=cookies)
    assert r2.status_code == 200
    assert "Development only" in r2.text and "plain text" in r2.text  # banner
    assert 'name="pin"' in r2.text
    assert "/-/demo-auth/callback" in r2.text

    # 3. the callback: the IdP hands back the typed subject + PIN + hints.
    qs = f"state={state}&subject={subject}&pin={pin}"
    if username is not None:
        qs += f"&username={username}"
    if name is not None:
        qs += f"&name={name}"
    return await ds.client.get(f"/-/demo-auth/callback?{qs}", cookies=cookies)


# ==========================================================================
# 1. Entry-point discovery + 2. disabled-by-default
# ==========================================================================


@pytest.mark.asyncio
async def test_demo_provider_discovered_via_entry_point():
    ds = await make_ds()
    registry = get_registry(ds)
    assert "demo" in registry  # discovered from the installed distribution
    assert registry["demo"].label == "Demo (dev only)"
    # Source is the demo package's top-level module, not datasette_accounts.
    from datasette_accounts.providers import provider_source

    assert provider_source(registry["demo"]) == "datasette_accounts_demo_auth"


@pytest.mark.asyncio
async def test_disabled_by_default_mount_404s():
    ds = await make_ds()  # installed but never enabled
    for sub in ("start", "idp", "callback"):
        r = await ds.client.get(f"/-/demo-auth/{sub}")
        assert r.status_code == 404, sub


# ==========================================================================
# 3. Approval flow: provision pending, approve, then sign in
# ==========================================================================


@pytest.mark.asyncio
async def test_approval_flow_end_to_end():
    ds = await make_ds()
    await _enable(ds, "demo", signups="approval")
    internal = ds.get_internal_database()

    # First contact → a pending account, derived username, no session.
    r = await _drive_login(ds, "alice-1", username="Alice")
    assert r.status_code == 200  # the awaiting-approval page, no redirect
    assert not r.cookies.get(COOKIE_NAME)

    ident = await db.get_identity(internal, "demo", "alice-1")
    assert ident is not None
    user = await db.get_user_by_id(internal, ident["user_id"])
    assert user["username"] == "alice"  # slugified from the "Alice" hint
    assert user["pending_approval"] == 1
    assert user["password_hash"] == UNUSABLE_PASSWORD
    assert await db.count_pending_users(internal) == 1

    # A second sign-in while still pending is refused (no session).
    r_pending = await _drive_login(ds, "alice-1", username="Alice")
    assert r_pending.status_code == 403
    assert not r_pending.cookies.get(COOKIE_NAME)

    # Approve, then the same identity signs in → a real session on the demo
    # provenance, usable against /-/account.
    await db.approve_user(internal, "root", ident["user_id"])
    r2 = await _drive_login(ds, "alice-1", username="Alice")
    assert r2.status_code == 302
    session = r2.cookies.get(COOKIE_NAME)
    assert session

    srows = await internal.execute(f"SELECT provider FROM {db.SESSIONS}")
    assert srows.rows[0][0] == "demo"

    account = await ds.client.get("/-/account", cookies={COOKIE_NAME: session})
    assert account.status_code == 200
    assert "alice" in account.text


# ==========================================================================
# 4. Auto-activate: first contact signs straight in
# ==========================================================================


@pytest.mark.asyncio
async def test_auto_activate_flow_end_to_end():
    ds = await make_ds()
    await _enable(ds, "demo", signups="auto")
    internal = ds.get_internal_database()

    r = await _drive_login(ds, "bob-99", username="Bob")
    assert r.status_code == 302
    assert r.cookies.get(COOKIE_NAME)

    ident = await db.get_identity(internal, "demo", "bob-99")
    user = await db.get_user_by_id(internal, ident["user_id"])
    assert user["username"] == "bob"
    assert user["pending_approval"] == 0

    srows = await internal.execute(f"SELECT provider FROM {db.SESSIONS}")
    assert [row[0] for row in srows.rows] == ["demo"]
    last = await internal.execute(
        f"SELECT reason, provider FROM {db.LOGIN_AUDIT} ORDER BY id DESC LIMIT 1"
    )
    assert dict(last.rows[0]) == {"reason": "success", "provider": "demo"}


@pytest.mark.asyncio
async def test_signups_off_is_generic_refusal():
    ds = await make_ds()
    await _enable(ds, "demo")  # signups absent → off
    r = await _drive_login(ds, "ghost")
    assert r.status_code == 403
    internal = ds.get_internal_database()
    assert (await internal.execute(f"SELECT COUNT(*) FROM {db.USERS}")).rows[0][0] == 0
    # The pretend IdP still claimed the subject: its PIN store is the "IdP's own
    # user database", independent of whether core provisions an account.
    pins = await internal.execute("SELECT COUNT(*) FROM demo_auth_pins")
    assert pins.rows[0][0] == 1


# ==========================================================================
# 5. Link flow: an existing password account links a demo identity
# ==========================================================================


@pytest.mark.asyncio
async def test_link_flow_end_to_end():
    ds = await make_ds()
    await _enable(ds, "demo")
    internal = ds.get_internal_database()
    uid = await insert_user(ds, "carol")  # has a password
    sess = await _session_cookie(ds, uid)

    # 1. link-start with the account password → a start_url + link-intent state.
    ls = await ds.client.post(
        "/-/account/api/link-start",
        content='{"provider": "demo", "password": "password123"}',
        headers=JSON,
        cookies={COOKIE_NAME: sess},
    )
    assert ls.status_code == 200
    start_url = ls.json()["start_url"]
    assert start_url.startswith("/-/demo-auth/start?state=")
    state_cookie = ls.cookies.get(STATE_COOKIE)
    assert state_cookie

    cookies = {COOKIE_NAME: sess, STATE_COOKIE: state_cookie}

    # 2. Drive the demo flow with that start_url (intent=link rides in the state).
    r1 = await ds.client.get(start_url, cookies=cookies)
    assert r1.status_code == 302
    idp_url = r1.headers["location"]
    assert idp_url.startswith("/-/demo-auth/idp?state=")
    state = _state_value(idp_url)

    # The IdP hands back a fresh subject (claiming its PIN) → callback links
    # it, never mints.
    r2 = await ds.client.get(
        f"/-/demo-auth/callback?state={state}&subject=gh-carol&pin=1234",
        cookies=cookies,
    )
    assert r2.status_code == 302
    assert r2.headers["location"].endswith("/-/account")
    assert not r2.cookies.get(COOKIE_NAME)  # linking never mints a session

    ident = await db.get_identity(internal, "demo", "gh-carol")
    assert ident is not None and ident["user_id"] == uid
    rows = await db.list_identities(internal, uid)
    assert [(r["provider"], r["subject"]) for r in rows] == [("demo", "gh-carol")]


@pytest.mark.asyncio
async def test_linked_identity_then_signs_in():
    """After linking, the same demo identity signs the linked account in
    directly (intent=login), minting a session — closing the loop."""
    ds = await make_ds()
    await _enable(ds, "demo")
    internal = ds.get_internal_database()
    uid = await insert_user(ds, "dave")
    await db.link_identity(
        internal, uid, uid, ExternalIdentity(provider="demo", subject="d-1")
    )

    r = await _drive_login(ds, "d-1")
    assert r.status_code == 302
    assert r.cookies.get(COOKIE_NAME)
    ident = await db.get_identity(internal, "demo", "d-1")
    assert ident["last_login_at"] is not None


@pytest.mark.asyncio
async def test_callback_without_state_fails():
    ds = await make_ds()
    await _enable(ds, "demo", signups="auto")
    # No state cookie, no state query arg → the provider's read_state guard
    # trips first, before any PIN handling.
    r = await ds.client.get("/-/demo-auth/callback?subject=x&pin=1234")
    assert r.status_code == 400


# ==========================================================================
# 6. PIN mechanics: claim on first use, verify after, reject malformed
# ==========================================================================

# The demo package's PIN table, by name — this file deliberately never imports
# the demo module (discovery is via the installed entry point alone).
DEMO_PINS = "demo_auth_pins"


@pytest.mark.asyncio
async def test_wrong_pin_bounces_back_without_a_session():
    ds = await make_ds()
    await _enable(ds, "demo", signups="auto")
    internal = ds.get_internal_database()

    # First sign-in claims the subject with PIN 1234 (auto signups → mints).
    r = await _drive_login(ds, "pin-1", pin="1234")
    assert r.status_code == 302
    assert r.cookies.get(COOKIE_NAME)

    # A wrong guess bounces back to the IdP form with the fixed error code —
    # no session, no extra account, no audit "success".
    r2 = await _drive_login(ds, "pin-1", pin="9999")
    assert r2.status_code == 302
    loc = r2.headers["location"]
    assert loc.startswith("/-/demo-auth/idp?")
    assert "error=wrong-pin" in loc
    assert not r2.cookies.get(COOKIE_NAME)
    # The bounced-to form renders the constant message (never user input).
    r3 = await ds.client.get(loc)
    assert "Wrong PIN for that subject." in r3.text

    # The right PIN still signs in, and the store holds one plaintext row.
    r4 = await _drive_login(ds, "pin-1", pin="1234")
    assert r4.status_code == 302
    assert r4.cookies.get(COOKIE_NAME)
    pins = await internal.execute(
        f"SELECT pin FROM {DEMO_PINS} WHERE subject = ?", ["pin-1"]
    )
    assert [row[0] for row in pins.rows] == ["1234"]  # plaintext, on purpose
    assert (await internal.execute(f"SELECT COUNT(*) FROM {db.SESSIONS}")).rows[0][
        0
    ] == 2  # the two correct-PIN sign-ins; the wrong guess minted nothing


@pytest.mark.asyncio
async def test_malformed_pin_never_touches_the_store():
    ds = await make_ds()
    await _enable(ds, "demo", signups="auto")
    internal = ds.get_internal_database()
    for bad in ("", "123", "12345", "12a4"):
        r = await _drive_login(ds, "mallory", pin=bad)
        assert r.status_code == 302, bad
        assert "error=bad-pin" in r.headers["location"], bad
        assert not r.cookies.get(COOKIE_NAME), bad
    # Nothing claimed, nobody provisioned — format is checked before the store.
    assert (await internal.execute(f"SELECT COUNT(*) FROM {DEMO_PINS}")).rows[0][0] == 0
    assert (await internal.execute(f"SELECT COUNT(*) FROM {db.USERS}")).rows[0][0] == 0
