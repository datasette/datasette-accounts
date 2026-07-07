"""Bootstrap homepage prompt (feature 1) + admin-editable site messages (feature 2)."""

import json

import pytest
from datasette.app import Datasette

from datasette_accounts import db
from datasette_accounts.passwords import hash_password
from datasette_accounts.security import COOKIE_NAME
from datasette_accounts.sessions import mint_token, token_sha256

JSON = {"content-type": "application/json"}


async def make_ds(**plugin_config):
    metadata = {}
    if plugin_config:
        metadata = {"plugins": {"datasette-accounts": plugin_config}}
    ds = Datasette(memory=True, metadata=metadata)
    await ds.invoke_startup()
    return ds


async def insert_user(ds, username, is_admin=False, disabled=False):
    internal = ds.get_internal_database()
    uid = db.new_id()
    ts = db.now_iso()
    await internal.execute_write(
        f"INSERT INTO {db.USERS} (id, username, password_hash, is_admin, disabled, "
        "must_change_password, failed_attempts, locked_until, created_at, updated_at) "
        "VALUES (?, ?, ?, ?, ?, 0, 0, NULL, ?, ?)",
        [uid, username, hash_password("x"), int(is_admin), int(disabled), ts, ts],
    )
    return uid


async def session_cookie(ds, actor_id):
    internal = ds.get_internal_database()
    raw = mint_token()
    await db.create_session(internal, actor_id, token_sha256(raw), 14, "ua", "1.1.1.1")
    from datasette_accounts.security import SIGN_NAMESPACE

    return {COOKIE_NAME: ds.sign(raw, SIGN_NAMESPACE)}


# --------------------------------------------------------------------------
# Feature 1 — bootstrap prompt on the homepage
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_bootstrap_prompt_shown_to_root_when_no_admin():
    ds = await make_ds()
    r = await ds.client.get("/", actor={"id": "root"})
    assert r.status_code == 200
    assert "Create the first admin account" in r.text


@pytest.mark.asyncio
async def test_bootstrap_prompt_gone_once_admin_exists():
    ds = await make_ds()
    await insert_user(ds, "boss", is_admin=True)
    r = await ds.client.get("/", actor={"id": "root"})
    assert "Create the first admin account" not in r.text


@pytest.mark.asyncio
async def test_bootstrap_prompt_ignores_disabled_admin():
    # A disabled admin does not count — root must still be prompted.
    ds = await make_ds()
    await insert_user(ds, "boss", is_admin=True, disabled=True)
    r = await ds.client.get("/", actor={"id": "root"})
    assert "Create the first admin account" in r.text


@pytest.mark.asyncio
async def test_bootstrap_prompt_not_shown_to_anonymous():
    ds = await make_ds()
    r = await ds.client.get("/")
    assert "Create the first admin account" not in r.text


@pytest.mark.asyncio
async def test_bootstrap_prompt_not_shown_to_non_root_user():
    ds = await make_ds()
    uid = await insert_user(ds, "alice")
    cookies = await session_cookie(ds, uid)
    r = await ds.client.get("/", cookies=cookies)
    assert "Create the first admin account" not in r.text


# --------------------------------------------------------------------------
# Feature 2 — admin-editable site messages
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_homepage_message_shown_only_to_signed_out():
    ds = await make_ds()
    internal = ds.get_internal_database()
    await db.set_site_message(internal, "root", "homepage_signed_out", "Please sign in")

    anon = await ds.client.get("/")
    assert "Please sign in" in anon.text

    uid = await insert_user(ds, "alice")
    cookies = await session_cookie(ds, uid)
    signed_in = await ds.client.get("/", cookies=cookies)
    assert "Please sign in" not in signed_in.text


@pytest.mark.asyncio
async def test_homepage_message_absent_when_unset():
    ds = await make_ds()
    r = await ds.client.get("/")
    # Nothing our hook injected — no banner div styling leaks through.
    assert "border-left:4px solid" not in r.text


@pytest.mark.asyncio
async def test_homepage_message_renders_raw_html():
    # Bodies are admin-authored HTML and rendered verbatim (see messages.py) so
    # admins can include links / mailto: contacts.
    ds = await make_ds()
    internal = ds.get_internal_database()
    await db.set_site_message(
        internal,
        "root",
        "homepage_signed_out",
        'Need access? <a href="mailto:it@corp.com">Email IT</a>.',
    )
    r = await ds.client.get("/")
    assert '<a href="mailto:it@corp.com">Email IT</a>' in r.text


@pytest.mark.asyncio
async def test_login_help_rendered_in_page_data():
    ds = await make_ds()
    internal = ds.get_internal_database()
    await db.set_site_message(
        internal, "root", "login_help", "Email alice@corp.com for access"
    )
    r = await ds.client.get("/-/login")
    assert "Email alice@corp.com for access" in r.text


# --- admin API ---


@pytest.mark.asyncio
async def test_admin_can_set_list_and_clear_message():
    ds = await make_ds()
    uid = await insert_user(ds, "boss", is_admin=True)
    cookies = await session_cookie(ds, uid)

    r = await ds.client.post(
        "/-/admin/api/messages/set",
        content=json.dumps({"key": "login_help", "body": "Ring the front desk"}),
        headers=JSON,
        cookies=cookies,
    )
    assert r.status_code == 200 and r.json()["ok"]
    internal = ds.get_internal_database()
    assert await db.get_site_message(internal, "login_help") == "Ring the front desk"

    listed = await ds.client.post(
        "/-/admin/api/messages/list", content="{}", headers=JSON, cookies=cookies
    )
    slots = {s["key"]: s for s in listed.json()["slots"]}
    assert slots["login_help"]["body"] == "Ring the front desk"
    assert slots["homepage_signed_out"]["body"] == ""

    # Blank body clears the slot (row is deleted).
    cleared = await ds.client.post(
        "/-/admin/api/messages/set",
        content=json.dumps({"key": "login_help", "body": "   "}),
        headers=JSON,
        cookies=cookies,
    )
    assert cleared.json() == {"ok": True, "body": ""}
    assert await db.get_site_message(internal, "login_help") is None


@pytest.mark.asyncio
async def test_set_message_rejects_unknown_slot():
    ds = await make_ds()
    uid = await insert_user(ds, "boss", is_admin=True)
    cookies = await session_cookie(ds, uid)
    r = await ds.client.post(
        "/-/admin/api/messages/set",
        content=json.dumps({"key": "bogus", "body": "x"}),
        headers=JSON,
        cookies=cookies,
    )
    assert r.status_code == 400


@pytest.mark.asyncio
async def test_messages_endpoints_require_admin():
    ds = await make_ds()
    uid = await insert_user(ds, "alice")  # not an admin
    cookies = await session_cookie(ds, uid)
    for path, body in [
        ("/-/admin/api/messages/list", "{}"),
        ("/-/admin/api/messages/set", json.dumps({"key": "login_help", "body": "x"})),
    ]:
        r = await ds.client.post(path, content=body, headers=JSON, cookies=cookies)
        assert r.status_code == 403


@pytest.mark.asyncio
async def test_messages_page_requires_admin():
    ds = await make_ds()
    uid = await insert_user(ds, "alice")
    cookies = await session_cookie(ds, uid)
    r = await ds.client.get("/-/admin/messages", cookies=cookies)
    assert r.status_code == 403


@pytest.mark.asyncio
async def test_set_site_message_unknown_slot_raises():
    ds = await make_ds()
    internal = ds.get_internal_database()
    with pytest.raises(ValueError):
        await db.set_site_message(internal, "root", "nope", "x")
