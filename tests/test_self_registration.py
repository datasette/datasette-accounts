"""Self-registration tracer (ticket 1 of plans/self-registration): a runtime
toggle gates /-/register; a visitor registers with their own password and
lands in a pending-approval queue that cannot log in or act.
"""

import json

import pytest
from datasette.app import Datasette

from datasette_accounts import db, security
from datasette_accounts.passwords import hash_password
from datasette_accounts.security import COOKIE_NAME, SIGN_NAMESPACE
from datasette_accounts.sessions import mint_token, token_sha256

JSON = {"content-type": "application/json"}


async def make_ds(**plugin_config):
    metadata = {}
    if plugin_config:
        metadata = {"plugins": {"datasette-accounts": plugin_config}}
    ds = Datasette(memory=True, metadata=metadata)
    await ds.invoke_startup()
    return ds


async def insert_user(ds, username, password="password123", is_admin=False):
    internal = ds.get_internal_database()
    user_id = db.new_id()
    ts = db.now_iso()
    await internal.execute_write(
        f"INSERT INTO {db.USERS} (id, username, password_hash, is_admin, disabled, "
        "must_change_password, failed_attempts, locked_until, created_at, updated_at) "
        "VALUES (?, ?, ?, ?, 0, 0, 0, NULL, ?, ?)",
        [user_id, username, hash_password(password), 1 if is_admin else 0, ts, ts],
    )
    return user_id


async def session_cookie(ds, actor_id):
    internal = ds.get_internal_database()
    raw = mint_token()
    await db.create_session(internal, actor_id, token_sha256(raw), 14, "ua", "1.1.1.1")
    return {COOKIE_NAME: ds.sign(raw, SIGN_NAMESPACE)}


async def login(ds, username, password, **extra):
    body = {"username": username, "password": password, **extra}
    r = await ds.client.post(
        "/-/login/api/authenticate", content=json.dumps(body), headers=JSON
    )
    cookie = r.cookies.get(COOKIE_NAME)
    return r, ({COOKIE_NAME: cookie} if cookie else {})


async def latest_reason(ds):
    internal = ds.get_internal_database()
    return (
        await internal.execute(
            f"SELECT reason FROM {db.LOGIN_AUDIT} ORDER BY id DESC LIMIT 1"
        )
    ).single_value()


# --------------------------------------------------------------------------
# Migration
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_migration_adds_settings_table_and_pending_column():
    ds = await make_ds()
    internal = ds.get_internal_database()
    tables = {
        r[0]
        for r in (
            await internal.execute(
                "SELECT name FROM sqlite_master WHERE type='table' "
                "AND name = 'datasette_accounts_settings'"
            )
        ).rows
    }
    assert tables == {"datasette_accounts_settings"}

    columns = {
        r["name"]
        for r in (await internal.execute(f"PRAGMA table_info({db.USERS})")).rows
    }
    assert "pending_approval" in columns


# --------------------------------------------------------------------------
# Toggle: default off, admin API flips it, audited both ways, no-ops
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_registration_disabled_by_default():
    ds = await make_ds()
    page = await ds.client.get("/-/register")
    assert page.status_code == 404

    submit = await ds.client.post(
        "/-/register/api/submit",
        content=json.dumps({"username": "newperson", "password": "password123"}),
        headers=JSON,
    )
    assert submit.status_code == 404


@pytest.mark.asyncio
async def test_toggle_requires_admin():
    ds = await make_ds()
    await insert_user(ds, "alice")  # not an admin
    _, cookies = await login(ds, "alice", "password123")
    r = await ds.client.post(
        "/-/admin/api/set-registration",
        content=json.dumps({"enabled": True}),
        headers=JSON,
        cookies=cookies,
    )
    assert r.status_code == 403
    internal = ds.get_internal_database()
    assert await db.get_registration_enabled(internal) is False


@pytest.mark.asyncio
async def test_toggle_on_makes_page_live_immediately_off_kills_submit():
    ds = await make_ds()
    await insert_user(ds, "boss", is_admin=True)
    _, cookies = await login(ds, "boss", "password123")

    on = await ds.client.post(
        "/-/admin/api/set-registration",
        content=json.dumps({"enabled": True}),
        headers=JSON,
        cookies=cookies,
    )
    assert on.status_code == 200
    assert on.json() == {"ok": True, "enabled": True}

    page = await ds.client.get("/-/register")
    assert page.status_code == 200

    submit_ok = await ds.client.post(
        "/-/register/api/submit",
        content=json.dumps({"username": "newperson", "password": "password123"}),
        headers=JSON,
    )
    assert submit_ok.status_code == 200
    assert submit_ok.json() == {"ok": True}

    # Flip off mid-session: the page 404s again and submit refuses, with no
    # restart in between.
    off = await ds.client.post(
        "/-/admin/api/set-registration",
        content=json.dumps({"enabled": False}),
        headers=JSON,
        cookies=cookies,
    )
    assert off.json() == {"ok": True, "enabled": False}

    page_again = await ds.client.get("/-/register")
    assert page_again.status_code == 404

    submit_again = await ds.client.post(
        "/-/register/api/submit",
        content=json.dumps({"username": "someoneelse", "password": "password123"}),
        headers=JSON,
    )
    assert submit_again.status_code == 404


@pytest.mark.asyncio
async def test_registration_page_redirects_signed_in_actor():
    ds = await make_ds()
    internal = ds.get_internal_database()
    await db.set_registration_enabled(internal, "root", True)
    await insert_user(ds, "alice")
    _, cookies = await login(ds, "alice", "password123")
    r = await ds.client.get("/-/register", cookies=cookies, follow_redirects=False)
    assert r.status_code in (301, 302, 303, 307, 308)


@pytest.mark.asyncio
async def test_toggle_audits_both_ways_and_noops_on_repeat():
    ds = await make_ds()
    internal = ds.get_internal_database()

    assert await db.set_registration_enabled(internal, "root", True) is True
    # Repeat flip to the same state is a no-op — no extra audit row.
    assert await db.set_registration_enabled(internal, "root", True) is True
    assert await db.set_registration_enabled(internal, "root", False) is False
    assert await db.set_registration_enabled(internal, "root", False) is False

    rows = (
        await internal.execute(
            f"SELECT operation FROM {db.ADMIN_AUDIT} "
            "WHERE operation IN ('enable-registration', 'disable-registration') "
            "ORDER BY id"
        )
    ).rows
    assert [r[0] for r in rows] == ["enable-registration", "disable-registration"]


# --------------------------------------------------------------------------
# Username validation (security.validate_username)
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "username",
    ["ab", "a" * 65, "_leading", "-leading", ".leading", "has space", "root", "ROOT"],
)
def test_validate_username_rejects(username):
    assert security.validate_username(username) is not None


@pytest.mark.parametrize("username", ["abc", "alice", "a.b_c-9", "A" * 64, "9start"])
def test_validate_username_accepts(username):
    assert security.validate_username(username) is None


@pytest.mark.asyncio
async def test_register_rejects_invalid_usernames():
    ds = await make_ds()
    internal = ds.get_internal_database()
    await db.set_registration_enabled(internal, "root", True)

    for bad_username in ["ab", "_bob", "has space", "root"]:
        r = await ds.client.post(
            "/-/register/api/submit",
            content=json.dumps({"username": bad_username, "password": "password123"}),
            headers=JSON,
        )
        assert r.status_code == 400, bad_username
        assert r.json()["ok"] is False

    assert await db.get_user_by_username(internal, "root") is None


@pytest.mark.asyncio
async def test_register_rejects_short_password():
    ds = await make_ds()
    internal = ds.get_internal_database()
    await db.set_registration_enabled(internal, "root", True)
    r = await ds.client.post(
        "/-/register/api/submit",
        content=json.dumps({"username": "newperson", "password": "short"}),
        headers=JSON,
    )
    assert r.status_code == 400
    assert await db.get_user_by_username(internal, "newperson") is None


# --------------------------------------------------------------------------
# Duplicate username, success, no session
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_register_duplicate_username_conflicts_and_audits_failure():
    ds = await make_ds()
    internal = ds.get_internal_database()
    await db.set_registration_enabled(internal, "root", True)
    await insert_user(ds, "alice")

    r = await ds.client.post(
        "/-/register/api/submit",
        content=json.dumps({"username": "alice", "password": "password123"}),
        headers=JSON,
    )
    assert r.status_code == 409
    assert r.json() == {"ok": False, "error": "Username already taken"}

    row = (
        await internal.execute(
            f"SELECT success, reason FROM {db.LOGIN_AUDIT} "
            "WHERE reason = 'register' ORDER BY id DESC LIMIT 1"
        )
    ).rows[0]
    assert (row[0], row[1]) == (0, "register")


@pytest.mark.asyncio
async def test_register_success_creates_pending_account_no_session():
    ds = await make_ds()
    internal = ds.get_internal_database()
    await db.set_registration_enabled(internal, "root", True)

    r = await ds.client.post(
        "/-/register/api/submit",
        content=json.dumps({"username": "newperson", "password": "password123"}),
        headers=JSON,
    )
    assert r.status_code == 200
    assert r.json() == {"ok": True}
    assert COOKIE_NAME not in r.cookies

    user = await db.get_user_by_username(internal, "newperson")
    assert user is not None
    assert user["pending_approval"] == 1
    assert user["must_change_password"] == 0
    assert user["is_admin"] == 0

    admin_audit = (
        await internal.execute(
            f"SELECT operation, actor_id, target_id, detail FROM {db.ADMIN_AUDIT} "
            "WHERE operation = 'register'"
        )
    ).rows
    assert len(admin_audit) == 1
    operation, actor_id, target_id, detail = admin_audit[0]
    assert actor_id is None
    assert target_id == user["id"]
    assert json.loads(detail)["username"] == "newperson"

    login_audit = (
        await internal.execute(
            f"SELECT success, reason, username FROM {db.LOGIN_AUDIT} "
            "WHERE reason = 'register'"
        )
    ).rows
    assert len(login_audit) == 1
    assert tuple(login_audit[0]) == (1, "register", "newperson")


# --------------------------------------------------------------------------
# Pending accounts can do nothing
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_pending_account_login_is_generic_and_burns_dummy_verify(monkeypatch):
    ds = await make_ds()
    internal = ds.get_internal_database()
    await db.set_registration_enabled(internal, "root", True)
    await ds.client.post(
        "/-/register/api/submit",
        content=json.dumps({"username": "newperson", "password": "password123"}),
        headers=JSON,
    )

    calls = {"n": 0}
    import datasette_accounts.routes.api as api

    real = api.averify_dummy

    async def counting(password):
        calls["n"] += 1
        return await real(password)

    monkeypatch.setattr(api, "averify_dummy", counting)

    r, cookies = await login(ds, "newperson", "password123")
    assert r.status_code == 401
    assert r.json() == {"ok": False, "error": "Invalid username or password"}
    assert not cookies
    # Same timing-safe shape as no-such-user/disabled/expired — the dummy KDF
    # verify still ran exactly once even though the real password is correct.
    assert calls["n"] == 1

    assert await latest_reason(ds) == "pending_approval"


@pytest.mark.asyncio
async def test_pending_account_resolves_no_actor_even_with_forged_session():
    # Defense in depth: even if a session somehow existed for a pending
    # account, resolve_actor must refuse it (mirrors the disabled-account check).
    ds = await make_ds()
    internal = ds.get_internal_database()
    await db.set_registration_enabled(internal, "root", True)
    await ds.client.post(
        "/-/register/api/submit",
        content=json.dumps({"username": "newperson", "password": "password123"}),
        headers=JSON,
    )
    user = await db.get_user_by_username(internal, "newperson")
    cookies = await session_cookie(ds, user["id"])

    who = await ds.client.get("/-/actor.json", cookies=cookies)
    assert who.json()["actor"] is None


@pytest.mark.asyncio
async def test_pending_account_excluded_from_valid_actors():
    from datasette.plugins import pm

    ds = await make_ds()
    internal = ds.get_internal_database()
    await db.set_registration_enabled(internal, "root", True)
    await ds.client.post(
        "/-/register/api/submit",
        content=json.dumps({"username": "newperson", "password": "password123"}),
        headers=JSON,
    )
    await insert_user(ds, "alice")

    results = []
    for hook_result in pm.hook.datasette_acl_valid_actors(datasette=ds):
        value = await hook_result() if callable(hook_result) else hook_result
        results.extend(value)
    displays = {r["display"] for r in results if isinstance(r, dict)}
    assert "alice" in displays
    assert "newperson" not in displays


@pytest.mark.asyncio
async def test_pending_account_rejected_as_grant_target():
    ds = await make_ds()
    internal = ds.get_internal_database()
    await db.set_registration_enabled(internal, "root", True)
    await ds.client.post(
        "/-/register/api/submit",
        content=json.dumps({"username": "newperson", "password": "password123"}),
        headers=JSON,
    )
    user = await db.get_user_by_username(internal, "newperson")

    with pytest.raises(db.InvalidGrantError):
        await db.grant_capability(
            internal,
            "root",
            action="some-global-action",
            principal_type="actor",
            target_actor_id=user["id"],
        )
