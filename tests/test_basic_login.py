import json

import pytest
from datasette.app import Datasette

from datasette_auth_basic_login import db
from datasette_auth_basic_login.passwords import hash_password
from datasette_auth_basic_login.security import COOKIE_NAME

JSON = {"content-type": "application/json"}


async def make_ds(**plugin_config):
    metadata = {}
    if plugin_config:
        metadata = {"plugins": {"datasette-auth-basic-login": plugin_config}}
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
):
    internal = ds.get_internal_database()
    user_id = db.new_id()
    ts = db.now_iso()
    await internal.execute_write(
        f"INSERT INTO {db.USERS} (id, username, password_hash, is_admin, disabled, "
        "must_change_password, failed_attempts, locked_until, created_at, updated_at) "
        "VALUES (?, ?, ?, ?, ?, ?, 0, NULL, ?, ?)",
        [
            user_id,
            username,
            hash_password(password),
            1 if is_admin else 0,
            1 if disabled else 0,
            1 if must_change_password else 0,
            ts,
            ts,
        ],
    )
    return user_id


async def login(ds, username, password, **extra):
    body = {"username": username, "password": password, **extra}
    r = await ds.client.post(
        "/-/login/api/authenticate", content=json.dumps(body), headers=JSON
    )
    cookie = r.cookies.get(COOKIE_NAME)
    return r, ({COOKIE_NAME: cookie} if cookie else {})


# --------------------------------------------------------------------------
# M0 / M1
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_plugin_installed_and_tables_created():
    ds = await make_ds()
    resp = await ds.client.get("/-/plugins.json")
    assert "datasette-auth-basic-login" in {p["name"] for p in resp.json()}
    internal = ds.get_internal_database()
    tables = await internal.execute(
        "SELECT name FROM sqlite_master WHERE type='table' "
        "AND name LIKE 'datasette_auth_basic_login%'"
    )
    assert sorted(r[0] for r in tables.rows) == [
        "datasette_auth_basic_login_admin_audit",
        "datasette_auth_basic_login_login_audit",
        "datasette_auth_basic_login_sessions",
        "datasette_auth_basic_login_users",
    ]


# --------------------------------------------------------------------------
# M3 — authentication
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_login_success_sets_cookie_and_actor():
    ds = await make_ds()
    await insert_user(ds, "alice")
    r, cookies = await login(ds, "alice", "password123")
    assert r.status_code == 200
    assert r.json()["ok"] is True
    assert cookies
    # authed request resolves the actor
    who = await ds.client.get("/-/actor.json", cookies=cookies)
    assert who.json()["actor"]["username"] == "alice"


@pytest.mark.asyncio
async def test_unknown_and_wrong_password_are_indistinguishable():
    ds = await make_ds()
    await insert_user(ds, "alice")
    r_unknown, _ = await login(ds, "ghost", "whatever")
    r_wrong, _ = await login(ds, "alice", "wrongpass")
    assert r_unknown.status_code == r_wrong.status_code == 401
    assert r_unknown.json() == r_wrong.json()


@pytest.mark.asyncio
async def test_unknown_username_still_verifies_once(monkeypatch):
    ds = await make_ds()
    calls = {"n": 0}
    import datasette_auth_basic_login.routes.api as api

    real = api.averify_dummy

    async def counting(password):
        calls["n"] += 1
        return await real(password)

    monkeypatch.setattr(api, "averify_dummy", counting)
    await login(ds, "ghost", "whatever")
    assert calls["n"] == 1  # dummy verify happened exactly once


@pytest.mark.asyncio
async def test_disabled_account_cannot_log_in():
    ds = await make_ds()
    await insert_user(ds, "bob", disabled=True)
    r, cookies = await login(ds, "bob", "password123")
    assert r.status_code == 401
    assert not cookies


@pytest.mark.asyncio
async def test_logout_destroys_session_but_get_does_not():
    ds = await make_ds()
    await insert_user(ds, "alice")
    _, cookies = await login(ds, "alice", "password123")
    internal = ds.get_internal_database()

    # GET /-/logout (the confirmation page) must not destroy the session,
    # and neither must a bare GET to the mutation endpoint.
    await ds.client.get("/-/logout", cookies=cookies)
    await ds.client.get("/-/logout/perform", cookies=cookies)
    count = (
        await internal.execute(f"SELECT COUNT(*) FROM {db.SESSIONS}")
    ).single_value()
    assert count == 1

    # POST /-/logout/perform does
    await ds.client.post(
        "/-/logout/perform", content="{}", headers=JSON, cookies=cookies
    )
    count = (
        await internal.execute(f"SELECT COUNT(*) FROM {db.SESSIONS}")
    ).single_value()
    assert count == 0


@pytest.mark.asyncio
async def test_lockout_after_threshold():
    ds = await make_ds(lockout_threshold=3, lockout_minutes=15)
    await insert_user(ds, "alice")
    for _ in range(3):
        r, _ = await login(ds, "alice", "wrong")
        assert r.status_code == 401
    # now locked -> 429 even with correct password
    r, cookies = await login(ds, "alice", "password123")
    assert r.status_code == 429
    assert not cookies


@pytest.mark.asyncio
async def test_concurrent_failures_increment_atomically():
    import asyncio

    ds = await make_ds(lockout_threshold=99)
    user_id = await insert_user(ds, "alice")
    internal = ds.get_internal_database()
    await asyncio.gather(
        *[db.register_failed_attempt(internal, user_id, 99, 15) for _ in range(2)]
    )
    count = (
        await internal.execute(
            f"SELECT failed_attempts FROM {db.USERS} WHERE id = ?", [user_id]
        )
    ).single_value()
    assert count == 2


@pytest.mark.asyncio
async def test_next_param_validation():
    ds = await make_ds()
    await insert_user(ds, "alice")
    cases = {
        "//evil.com": "/",
        "/\\evil.com": "/",
        "https://evil.com": "/",
        "javascript:alert(1)": "/",
        "%2F%2Fevil.com": "/",
        "/ok/path?x=1": "/ok/path?x=1",
    }
    for value, expected in cases.items():
        r, _ = await login(ds, "alice", "password123", next=value)
        assert r.json()["redirect"] == expected, value


# --------------------------------------------------------------------------
# CSRF
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_csrf_content_type_required():
    ds = await make_ds()
    await insert_user(ds, "alice")
    body = json.dumps({"username": "alice", "password": "password123"})
    r = await ds.client.post(
        "/-/login/api/authenticate",
        content=body,
        headers={"content-type": "text/plain"},
    )
    assert r.status_code == 403


@pytest.mark.asyncio
async def test_csrf_cross_site_rejected():
    ds = await make_ds()
    await insert_user(ds, "alice")
    body = json.dumps({"username": "alice", "password": "password123"})
    r = await ds.client.post(
        "/-/login/api/authenticate",
        content=body,
        headers={"content-type": "application/json", "sec-fetch-site": "cross-site"},
    )
    assert r.status_code == 403


# --------------------------------------------------------------------------
# M4 — admin
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_admin_action_grant_and_disabled_denied():
    ds = await make_ds()
    admin_id = await insert_user(ds, "admin", is_admin=True)
    disabled_admin_id = await insert_user(ds, "olddmin", is_admin=True, disabled=True)
    non_admin_id = await insert_user(ds, "bob")

    async def allowed(actor):
        return await ds.allowed(action="datasette-auth-basic-login-admin", actor=actor)

    assert await allowed({"id": admin_id})
    assert await allowed({"id": "root"})
    assert not await allowed({"id": non_admin_id})
    # disabled admin denied even if actor dict forges is_admin
    assert not await allowed({"id": disabled_admin_id, "is_admin": True})


@pytest.mark.asyncio
async def test_non_admin_cannot_call_admin_api():
    ds = await make_ds()
    await insert_user(ds, "bob")
    _, cookies = await login(ds, "bob", "password123")
    r = await ds.client.post(
        "/-/admin/api/create",
        content=json.dumps({"username": "x", "password": "password123"}),
        headers=JSON,
        cookies=cookies,
    )
    assert r.status_code == 403


@pytest.mark.asyncio
async def test_admin_create_and_audit():
    ds = await make_ds()
    await insert_user(ds, "admin", is_admin=True)
    _, cookies = await login(ds, "admin", "password123")
    r = await ds.client.post(
        "/-/admin/api/create",
        content=json.dumps({"username": "carol", "password": "password123"}),
        headers=JSON,
        cookies=cookies,
    )
    assert r.status_code == 200 and r.json()["ok"]
    internal = ds.get_internal_database()
    audit = await internal.execute(
        f"SELECT operation, target_id FROM {db.ADMIN_AUDIT} WHERE operation='create'"
    )
    rows = list(audit.rows)
    assert len(rows) == 1 and rows[0][1] == r.json()["id"]


@pytest.mark.asyncio
async def test_last_admin_guard():
    ds = await make_ds()
    admin_id = await insert_user(ds, "admin", is_admin=True)
    _, cookies = await login(ds, "admin", "password123")
    for op in ("disable", "delete", "toggle-admin"):
        r = await ds.client.post(
            f"/-/admin/api/{op}",
            content=json.dumps({"id": admin_id}),
            headers=JSON,
            cookies=cookies,
        )
        assert r.status_code == 409, op


@pytest.mark.asyncio
async def test_reset_password_revokes_sessions():
    ds = await make_ds()
    await insert_user(ds, "admin", is_admin=True)
    bob_id = await insert_user(ds, "bob")
    _, bob_cookies = await login(ds, "bob", "password123")
    _, admin_cookies = await login(ds, "admin", "password123")
    internal = ds.get_internal_database()
    assert (
        await internal.execute(
            f"SELECT COUNT(*) FROM {db.SESSIONS} WHERE actor_id=?", [bob_id]
        )
    ).single_value() == 1
    r = await ds.client.post(
        "/-/admin/api/reset-password",
        content=json.dumps({"id": bob_id, "password": "newpassword1"}),
        headers=JSON,
        cookies=admin_cookies,
    )
    assert r.status_code == 200
    assert (
        await internal.execute(
            f"SELECT COUNT(*) FROM {db.SESSIONS} WHERE actor_id=?", [bob_id]
        )
    ).single_value() == 0


# --------------------------------------------------------------------------
# M5 — self-service + forced change
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_change_password_flow():
    ds = await make_ds()
    await insert_user(ds, "alice")
    _, cookies = await login(ds, "alice", "password123")
    # wrong current -> 401
    r = await ds.client.post(
        "/-/account/api/change-password",
        content=json.dumps({"current_password": "nope", "new_password": "brandnew1"}),
        headers=JSON,
        cookies=cookies,
    )
    assert r.status_code == 401
    # right current -> ok
    r = await ds.client.post(
        "/-/account/api/change-password",
        content=json.dumps(
            {"current_password": "password123", "new_password": "brandnew1"}
        ),
        headers=JSON,
        cookies=cookies,
    )
    assert r.status_code == 200
    # old password no longer works
    r2, _ = await login(ds, "alice", "password123")
    assert r2.status_code == 401
    r3, _ = await login(ds, "alice", "brandnew1")
    assert r3.status_code == 200


@pytest.mark.asyncio
async def test_change_password_shares_lockout():
    ds = await make_ds(lockout_threshold=3)
    await insert_user(ds, "alice")
    _, cookies = await login(ds, "alice", "password123")
    for _ in range(3):
        await ds.client.post(
            "/-/account/api/change-password",
            content=json.dumps(
                {"current_password": "wrong", "new_password": "brandnew1"}
            ),
            headers=JSON,
            cookies=cookies,
        )
    # login now locked
    r, _ = await login(ds, "alice", "password123")
    assert r.status_code == 429


@pytest.mark.asyncio
async def test_must_change_password_gate():
    ds = await make_ds()
    await insert_user(ds, "alice", must_change_password=True)
    _, cookies = await login(ds, "alice", "password123")
    # blocked from a core route
    r = await ds.client.get("/", cookies=cookies)
    assert r.status_code == 302
    assert "/-/account" in r.headers["location"]
    # account page still reachable
    r = await ds.client.get("/-/account", cookies=cookies)
    assert r.status_code == 200
    # after changing, full access restored
    await ds.client.post(
        "/-/account/api/change-password",
        content=json.dumps(
            {"current_password": "password123", "new_password": "brandnew1"}
        ),
        headers=JSON,
        cookies=cookies,
    )
    r = await ds.client.get("/", cookies=cookies)
    assert r.status_code == 200


# --------------------------------------------------------------------------
# M2 — passwords + retention
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_password_max_length_enforced():
    ds = await make_ds()
    await insert_user(ds, "admin", is_admin=True)
    _, cookies = await login(ds, "admin", "password123")
    r = await ds.client.post(
        "/-/admin/api/create",
        content=json.dumps({"username": "big", "password": "x" * 1025}),
        headers=JSON,
        cookies=cookies,
    )
    assert r.status_code == 400


@pytest.mark.asyncio
async def test_audit_retention_purges_old_rows():
    ds = await make_ds(audit_retention_days=30)
    internal = ds.get_internal_database()
    await internal.execute_write(
        f"INSERT INTO {db.LOGIN_AUDIT} (username, ip, timestamp, success) "
        "VALUES (?, ?, ?, ?)",
        ["old", None, "2000-01-01T00:00:00+00:00", 0],
    )
    await db.purge_login_audit(internal, 30)
    count = (
        await internal.execute(f"SELECT COUNT(*) FROM {db.LOGIN_AUDIT}")
    ).single_value()
    assert count == 0
