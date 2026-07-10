import json
import re

import pytest
from datasette.app import Datasette

from datasette_accounts import db
from datasette_accounts.passwords import hash_password
from datasette_accounts.security import COOKIE_NAME, SIGN_NAMESPACE
from datasette_accounts.sessions import token_sha256

JSON = {"content-type": "application/json"}

PAGE_DATA_RE = re.compile(
    r'<script type="application/json" id="pageData">(.*?)</script>', re.S
)


def extract_page_data(html):
    return json.loads(PAGE_DATA_RE.search(html).group(1))


async def make_ds(**plugin_config):
    metadata = {}
    if plugin_config:
        metadata = {"plugins": {"datasette-accounts": plugin_config}}
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
    expires_at=None,
):
    internal = ds.get_internal_database()
    user_id = db.new_id()
    ts = db.now_iso()
    await internal.execute_write(
        f"INSERT INTO {db.USERS} (id, username, password_hash, is_admin, disabled, "
        "must_change_password, failed_attempts, locked_until, created_at, updated_at, "
        "expires_at) "
        "VALUES (?, ?, ?, ?, ?, ?, 0, NULL, ?, ?, ?)",
        [
            user_id,
            username,
            hash_password(password),
            1 if is_admin else 0,
            1 if disabled else 0,
            1 if must_change_password else 0,
            ts,
            ts,
            expires_at,
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
    assert "datasette-accounts" in {p["name"] for p in resp.json()}
    internal = ds.get_internal_database()
    tables = await internal.execute(
        "SELECT name FROM sqlite_master WHERE type='table' "
        "AND name LIKE 'datasette_accounts%'"
    )
    assert sorted(r[0] for r in tables.rows) == [
        "datasette_accounts_admin_audit",
        "datasette_accounts_capability_grants",
        "datasette_accounts_identities",
        "datasette_accounts_login_audit",
        "datasette_accounts_password_tokens",
        "datasette_accounts_sessions",
        "datasette_accounts_settings",
        "datasette_accounts_site_messages",
        "datasette_accounts_users",
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
async def test_last_login_at_tracks_first_signin():
    ds = await make_ds()
    await insert_user(ds, "admin", is_admin=True)
    await insert_user(ds, "bob")

    def by_name(users):
        return {u["username"]: u for u in users}

    _, admin_cookies = await login(ds, "admin", "password123")
    listed = await ds.client.post(
        "/-/admin/api/list", content="{}", headers=JSON, cookies=admin_cookies
    )
    users = by_name(listed.json()["users"])
    # bob has never signed in -> pending
    assert users["bob"]["last_login_at"] is None

    # bob signs in for the first time...
    await login(ds, "bob", "password123")
    listed = await ds.client.post(
        "/-/admin/api/list", content="{}", headers=JSON, cookies=admin_cookies
    )
    users = by_name(listed.json()["users"])
    assert users["bob"]["last_login_at"] is not None


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
    import datasette_accounts.routes.api as api

    real = api.averify_dummy

    async def counting(password):
        calls["n"] += 1
        return await real(password)

    monkeypatch.setattr(api, "averify_dummy", counting)
    await login(ds, "ghost", "whatever")
    assert calls["n"] == 1  # dummy verify happened exactly once


def test_unusable_password_sentinel_never_verifies():
    from datasette_accounts.passwords import UNUSABLE_PASSWORD, verify_password

    # Defensive: nothing (including the sentinel itself, or an empty
    # password) can ever verify against the sentinel — this is what makes the
    # change-password re-auth path safe even if it were ever reached for an
    # unusable-password account.
    assert verify_password("", UNUSABLE_PASSWORD) is False
    assert verify_password("anything", UNUSABLE_PASSWORD) is False
    assert verify_password(UNUSABLE_PASSWORD, UNUSABLE_PASSWORD) is False


@pytest.mark.asyncio
async def test_invited_account_login_burns_dummy_verify_and_is_generic(monkeypatch):
    ds = await make_ds()
    internal = ds.get_internal_database()
    await db.create_invited_user(
        internal,
        actor_id=None,
        username="invitee",
        is_admin=False,
        token_sha="tok1",
        ttl_hours=72,
    )

    calls = {"n": 0}
    import datasette_accounts.routes.api as api

    real = api.averify_dummy

    async def counting(password):
        calls["n"] += 1
        return await real(password)

    monkeypatch.setattr(api, "averify_dummy", counting)

    r, cookies = await login(ds, "invitee", "whatever")
    assert r.status_code == 401
    assert r.json() == {"ok": False, "error": "Invalid username or password"}
    assert not cookies
    # Not a fast path: the dummy KDF verify still ran exactly once, same as
    # the no-such-user branch — an invited account must not be distinguishable
    # by timing.
    assert calls["n"] == 1

    reason = (
        await internal.execute(
            f"SELECT reason FROM {db.LOGIN_AUDIT} ORDER BY id DESC LIMIT 1"
        )
    ).single_value()
    assert reason == "no_password"


@pytest.mark.asyncio
async def test_invited_account_login_indistinguishable_from_unknown_user():
    ds = await make_ds()
    internal = ds.get_internal_database()
    await db.create_invited_user(
        internal,
        actor_id=None,
        username="invitee",
        is_admin=False,
        token_sha="tok1",
        ttl_hours=72,
    )
    r_invited, _ = await login(ds, "invitee", "whatever")
    r_unknown, _ = await login(ds, "ghost", "whatever")
    assert r_invited.status_code == r_unknown.status_code == 401
    assert r_invited.json() == r_unknown.json()


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
async def test_login_and_logout_clear_stale_core_actor_cookie():
    # A leftover core `ds_actor` cookie (e.g. an old root login) makes
    # Datasette's base template render a second Log out button; our login and
    # logout responses must expire it. No ds_actor cookie → no Set-Cookie.
    ds = await make_ds()
    await insert_user(ds, "alice")

    r = await ds.client.post(
        "/-/login/api/authenticate",
        content=json.dumps({"username": "alice", "password": "password123"}),
        headers=JSON,
        cookies={"ds_actor": "stale"},
    )
    assert r.status_code == 200
    set_cookies = r.headers.get_list("set-cookie")
    assert any(c.startswith('ds_actor="";') for c in set_cookies)

    cookies = {COOKIE_NAME: r.cookies.get(COOKIE_NAME)}
    r = await ds.client.post(
        "/-/logout/perform",
        content="{}",
        headers=JSON,
        cookies={**cookies, "ds_actor": "stale"},
    )
    assert any(
        c.startswith('ds_actor="";') for c in r.headers.get_list("set-cookie")
    )

    # Without the stale cookie, nothing touches ds_actor.
    _, cookies = await login(ds, "alice", "password123")
    r = await ds.client.post(
        "/-/logout/perform", content="{}", headers=JSON, cookies=cookies
    )
    assert not any(
        c.startswith("ds_actor=") for c in r.headers.get_list("set-cookie")
    )


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
        return await ds.allowed(action="datasette-accounts-admin", actor=actor)

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


@pytest.mark.asyncio
async def test_admin_create_generated_password():
    ds = await make_ds()
    await insert_user(ds, "admin", is_admin=True)
    _, cookies = await login(ds, "admin", "password123")
    r = await ds.client.post(
        "/-/admin/api/create",
        content=json.dumps({"username": "carol", "generate": True}),
        headers=JSON,
        cookies=cookies,
    )
    assert r.status_code == 200
    body = r.json()
    generated = body["password"]
    # A real, strong password is echoed back exactly once.
    assert generated and len(generated) >= 20
    # The generated password actually authenticates.
    login_r, _ = await login(ds, "carol", generated)
    assert login_r.json()["ok"]


@pytest.mark.asyncio
async def test_admin_reset_generated_password():
    ds = await make_ds()
    await insert_user(ds, "admin", is_admin=True)
    bob_id = await insert_user(ds, "bob")
    _, cookies = await login(ds, "admin", "password123")
    r = await ds.client.post(
        "/-/admin/api/reset-password",
        content=json.dumps({"id": bob_id, "generate": True}),
        headers=JSON,
        cookies=cookies,
    )
    assert r.status_code == 200
    generated = r.json()["password"]
    assert generated
    # Old password stops working; the generated one logs in.
    old_r, _ = await login(ds, "bob", "password123")
    assert not old_r.json()["ok"]
    new_r, _ = await login(ds, "bob", generated)
    assert new_r.json()["ok"]


@pytest.mark.asyncio
async def test_admin_supplied_password_not_echoed():
    ds = await make_ds()
    await insert_user(ds, "admin", is_admin=True)
    _, cookies = await login(ds, "admin", "password123")
    r = await ds.client.post(
        "/-/admin/api/create",
        content=json.dumps({"username": "dave", "password": "password123"}),
        headers=JSON,
        cookies=cookies,
    )
    assert r.status_code == 200
    # An admin-supplied password is never reflected back in the response.
    assert r.json().get("password") is None


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


@pytest.mark.asyncio
async def test_change_password_rejects_reuse():
    ds = await make_ds()
    await insert_user(ds, "alice")
    _, cookies = await login(ds, "alice", "password123")
    r = await ds.client.post(
        "/-/account/api/change-password",
        content=json.dumps(
            {"current_password": "password123", "new_password": "password123"}
        ),
        headers=JSON,
        cookies=cookies,
    )
    assert r.status_code == 400
    assert "different" in r.json()["error"].lower()


@pytest.mark.asyncio
async def test_admin_reset_same_password_no_oracle():
    # Deliberately NO differs-from-current check on the admin path: a 400 for
    # "same password" would let an admin test guesses against a user's real
    # password. Resetting to the same value succeeds and still revokes sessions.
    ds = await make_ds()
    await insert_user(ds, "admin", is_admin=True)
    bob_id = await insert_user(ds, "bob")
    _, bob_cookies = await login(ds, "bob", "password123")
    _, cookies = await login(ds, "admin", "password123")
    r = await ds.client.post(
        "/-/admin/api/reset-password",
        content=json.dumps({"id": bob_id, "password": "password123"}),
        headers=JSON,
        cookies=cookies,
    )
    assert r.status_code == 200
    assert r.json() == {"ok": True}
    internal = ds.get_internal_database()
    count = (
        await internal.execute(
            f"SELECT COUNT(*) FROM {db.SESSIONS} WHERE actor_id=?", [bob_id]
        )
    ).single_value()
    assert count == 0


@pytest.mark.asyncio
async def test_forced_change_needs_no_current_password():
    ds = await make_ds()
    await insert_user(ds, "alice", must_change_password=True)
    _, cookies = await login(ds, "alice", "password123")
    # First-login change succeeds without re-supplying the current password.
    r = await ds.client.post(
        "/-/account/api/change-password",
        content=json.dumps({"new_password": "brandnew1"}),
        headers=JSON,
        cookies=cookies,
    )
    assert r.status_code == 200
    # Gate lifted and the new password authenticates.
    assert (await ds.client.get("/", cookies=cookies)).status_code == 200
    assert (await login(ds, "alice", "brandnew1"))[0].status_code == 200


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


@pytest.mark.asyncio
async def test_login_attempts_record_reason():
    ds = await make_ds()
    await insert_user(ds, "alice")
    await insert_user(ds, "bob", disabled=True)

    await login(ds, "alice", "password123")  # success
    await login(ds, "alice", "wrongpass")  # bad_password
    await login(ds, "ghost", "whatever")  # no_such_user
    await login(ds, "bob", "password123")  # disabled

    internal = ds.get_internal_database()
    rows = await internal.execute(
        f"SELECT username, success, reason FROM {db.LOGIN_AUDIT} ORDER BY id"
    )
    got = [(r["username"], r["success"], r["reason"]) for r in rows.rows]
    assert got == [
        ("alice", 1, "success"),
        ("alice", 0, "bad_password"),
        ("ghost", 0, "no_such_user"),
        ("bob", 0, "disabled"),
    ]


@pytest.mark.asyncio
async def test_locked_account_records_locked_reason():
    ds = await make_ds(lockout_threshold=2, lockout_minutes=15)
    await insert_user(ds, "alice")
    # Two failures trip the lockout; the third attempt is refused pre-hash.
    await login(ds, "alice", "wrong")
    await login(ds, "alice", "wrong")
    await login(ds, "alice", "wrong")
    internal = ds.get_internal_database()
    reason = (
        await internal.execute(
            f"SELECT reason FROM {db.LOGIN_AUDIT} ORDER BY id DESC LIMIT 1"
        )
    ).single_value()
    assert reason == "locked"


@pytest.mark.asyncio
async def test_list_login_attempts_filters():
    ds = await make_ds()
    internal = ds.get_internal_database()
    await db.record_login_attempt(internal, "alice", "1.1.1.1", True, "success")
    await db.record_login_attempt(internal, "alice", "2.2.2.2", False, "bad_password")
    await db.record_login_attempt(internal, "bob", "1.1.1.1", False, "no_such_user")

    by_user = await db.list_login_attempts(internal, username="alice")
    assert [r["reason"] for r in by_user] == ["bad_password", "success"]  # id DESC

    by_ip = await db.list_login_attempts(internal, ip="1.1.1.1")
    assert {r["username"] for r in by_ip} == {"alice", "bob"}

    by_both = await db.list_login_attempts(internal, username="alice", ip="1.1.1.1")
    assert len(by_both) == 1 and by_both[0]["reason"] == "success"


# --------------------------------------------------------------------------
# Admin audit — codegen promotion, filters, retention
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_list_admin_audit_resolves_usernames():
    ds = await make_ds()
    admin_id = await insert_user(ds, "admin", is_admin=True)
    internal = ds.get_internal_database()
    target_id = await db.create_user(
        internal, admin_id, "carol", hash_password("password123"), False, False
    )
    rows = await db.list_admin_audit(internal)
    assert len(rows) == 1
    row = rows[0]
    assert row["operation"] == "create"
    assert row["actor_id"] == admin_id
    assert row["actor_username"] == "admin"
    assert row["target_id"] == target_id
    assert row["target_username"] == "carol"


@pytest.mark.asyncio
async def test_list_admin_audit_target_and_operation_filters_and_combine():
    ds = await make_ds()
    admin_id = await insert_user(ds, "admin", is_admin=True)
    internal = ds.get_internal_database()
    alice_id = await db.create_user(
        internal, admin_id, "alice", hash_password("password123"), False, False
    )
    bob_id = await db.create_user(
        internal, admin_id, "bob", hash_password("password123"), False, False
    )
    await db.disable_user(internal, admin_id, alice_id)
    await db.disable_user(internal, admin_id, bob_id)

    # target_id alone: both of alice's rows (create + disable).
    by_target = await db.list_admin_audit(internal, target_id=alice_id)
    assert {r["operation"] for r in by_target} == {"create", "disable"}
    assert all(r["target_id"] == alice_id for r in by_target)

    # operation alone: every disable, regardless of target.
    by_operation = await db.list_admin_audit(internal, operation="disable")
    assert {r["target_id"] for r in by_operation} == {alice_id, bob_id}

    # Both together AND-combine to a single row.
    by_both = await db.list_admin_audit(
        internal, target_id=alice_id, operation="disable"
    )
    assert len(by_both) == 1
    assert by_both[0]["target_id"] == alice_id
    assert by_both[0]["operation"] == "disable"

    # A mismatched pair yields nothing.
    none = await db.list_admin_audit(internal, target_id=alice_id, operation="delete")
    assert none == []


@pytest.mark.asyncio
async def test_list_admin_audit_deleted_target_falls_back_to_id():
    ds = await make_ds()
    admin_id = await insert_user(ds, "admin", is_admin=True)
    internal = ds.get_internal_database()
    target_id = await db.create_user(
        internal, admin_id, "carol", hash_password("password123"), False, False
    )
    await db.delete_user(internal, admin_id, target_id)

    rows = await db.list_admin_audit(internal, operation="delete")
    assert len(rows) == 1
    assert rows[0]["target_id"] == target_id
    assert rows[0]["target_username"] is None


@pytest.mark.asyncio
async def test_list_admin_audit_operations_distinct_and_sorted():
    ds = await make_ds()
    admin_id = await insert_user(ds, "admin", is_admin=True)
    internal = ds.get_internal_database()
    alice_id = await db.create_user(
        internal, admin_id, "alice", hash_password("password123"), False, False
    )
    bob_id = await db.create_user(
        internal, admin_id, "bob", hash_password("password123"), False, False
    )
    await db.disable_user(internal, admin_id, alice_id)
    await db.disable_user(internal, admin_id, bob_id)

    ops = await db.list_admin_audit_operations(internal)
    assert ops == ["create", "disable"]  # distinct + alphabetically sorted


@pytest.mark.asyncio
async def test_admin_audit_retention_zero_keeps_everything():
    ds = await make_ds(admin_audit_retention_days=0)
    internal = ds.get_internal_database()
    await internal.execute_write(
        f"INSERT INTO {db.ADMIN_AUDIT} (timestamp, operation, actor_id, target_id, detail) "
        "VALUES (?, ?, ?, ?, ?)",
        ["2000-01-01T00:00:00.000+00:00", "create", "root", "old", None],
    )
    await db.purge_admin_audit(internal, 0)
    count = (
        await internal.execute(f"SELECT COUNT(*) FROM {db.ADMIN_AUDIT}")
    ).single_value()
    assert count == 1


@pytest.mark.asyncio
async def test_admin_audit_retention_purges_only_old_rows():
    ds = await make_ds(admin_audit_retention_days=30)
    internal = ds.get_internal_database()
    await internal.execute_write(
        f"INSERT INTO {db.ADMIN_AUDIT} (timestamp, operation, actor_id, target_id, detail) "
        "VALUES (?, ?, ?, ?, ?)",
        ["2000-01-01T00:00:00.000+00:00", "create", "root", "old", None],
    )
    await internal.execute_write(
        f"INSERT INTO {db.ADMIN_AUDIT} (timestamp, operation, actor_id, target_id, detail) "
        "VALUES (?, ?, ?, ?, ?)",
        [db.now_iso(), "create", "root", "new", None],
    )
    await db.purge_admin_audit(internal, 30)
    remaining = await internal.execute(f"SELECT target_id FROM {db.ADMIN_AUDIT}")
    assert [r[0] for r in remaining.rows] == ["new"]


@pytest.mark.asyncio
async def test_list_admin_audit_limit_clamps_at_500():
    ds = await make_ds()
    internal = ds.get_internal_database()
    now = db.now_iso()
    await internal.execute_write_many(
        f"INSERT INTO {db.ADMIN_AUDIT} (timestamp, operation, actor_id, target_id, detail) "
        "VALUES (?, ?, ?, ?, ?)",
        [(now, "create", "root", str(i), None) for i in range(510)],
    )
    rows = await db.list_admin_audit(internal, limit=10_000)
    assert len(rows) == db.ADMIN_AUDIT_MAX


@pytest.mark.asyncio
async def test_admin_login_attempts_api():
    ds = await make_ds()
    await insert_user(ds, "admin", is_admin=True)
    internal = ds.get_internal_database()
    await db.record_login_attempt(internal, "victim", "9.9.9.9", False, "bad_password")

    _, cookies = await login(ds, "admin", "password123")
    r = await ds.client.post(
        "/-/admin/api/login-attempts",
        content=json.dumps({"username": "victim"}),
        headers=JSON,
        cookies=cookies,
    )
    assert r.status_code == 200
    data = r.json()
    assert data["ok"]
    assert [a["reason"] for a in data["attempts"]] == ["bad_password"]
    assert data["attempts"][0]["ip"] == "9.9.9.9"


# --------------------------------------------------------------------------
# Account expiry
# --------------------------------------------------------------------------

PAST = "2020-01-01T00:00:00.000+00:00"
FUTURE = "2099-01-01T00:00:00.000+00:00"


@pytest.mark.asyncio
async def test_expired_account_cannot_log_in(monkeypatch):
    ds = await make_ds()
    await insert_user(ds, "temp", expires_at=PAST)

    calls = {"n": 0}
    import datasette_accounts.routes.api as api

    real = api.averify_dummy

    async def counting(password):
        calls["n"] += 1
        return await real(password)

    monkeypatch.setattr(api, "averify_dummy", counting)

    r, cookies = await login(ds, "temp", "password123")
    assert r.status_code == 401
    assert r.json() == {"ok": False, "error": "Invalid username or password"}
    assert not cookies
    # Takes the dummy-verify branch — same timing-safe shape as no-such-user /
    # disabled / no-password.
    assert calls["n"] == 1

    internal = ds.get_internal_database()
    reason = (
        await internal.execute(
            f"SELECT reason FROM {db.LOGIN_AUDIT} ORDER BY id DESC LIMIT 1"
        )
    ).single_value()
    assert reason == "expired"


@pytest.mark.asyncio
async def test_unexpired_account_still_logs_in():
    ds = await make_ds()
    await insert_user(ds, "temp", expires_at=FUTURE)
    r, cookies = await login(ds, "temp", "password123")
    assert r.status_code == 200
    assert cookies


@pytest.mark.asyncio
async def test_live_session_dies_once_expiry_passes():
    ds = await make_ds()
    await insert_user(ds, "temp", expires_at=FUTURE)
    r, cookies = await login(ds, "temp", "password123")
    assert r.status_code == 200

    # Still resolves while the deadline is in the future.
    who = await ds.client.get("/-/actor.json", cookies=cookies)
    assert who.json()["actor"]["username"] == "temp"

    # Push the deadline into the past directly (no clock mocking) — the same
    # session token must stop resolving on the very next request.
    internal = ds.get_internal_database()
    await internal.execute_write(
        f"UPDATE {db.USERS} SET expires_at = ? WHERE username = 'temp'", [PAST]
    )
    who = await ds.client.get("/-/actor.json", cookies=cookies)
    assert who.json()["actor"] is None


# --------------------------------------------------------------------------
# Account expiry — set/clear API (POST /-/admin/api/set-expiry)
# --------------------------------------------------------------------------


async def _admin_and_target(ds):
    """An admin session plus a plain target account; returns (cookies, uid)."""
    await insert_user(ds, "admin", is_admin=True)
    uid = await insert_user(ds, "temp")
    _, cookies = await login(ds, "admin", "password123")
    return cookies, uid


async def _set_expiry(ds, cookies, **body):
    return await ds.client.post(
        "/-/admin/api/set-expiry",
        content=json.dumps(body),
        headers=JSON,
        cookies=cookies,
    )


@pytest.mark.asyncio
async def test_set_expiry_api_requires_admin():
    ds = await make_ds()
    await insert_user(ds, "plain")
    _, cookies = await login(ds, "plain", "password123")
    r = await _set_expiry(ds, cookies, id="whatever", in_days=30)
    assert r.status_code == 403


@pytest.mark.asyncio
async def test_set_expiry_api_rejects_both_forms_and_bad_values():
    ds = await make_ds()
    cookies, uid = await _admin_and_target(ds)

    r = await _set_expiry(ds, cookies, id=uid, expires_at="2099-01-01", in_days=30)
    assert r.status_code == 400
    assert "not both" in r.json()["error"]

    for bad in (
        {"expires_at": "not a date"},
        {"expires_at": "2020-01-01"},
        {"in_days": 0},
        {"in_days": -3},
    ):
        r = await _set_expiry(ds, cookies, id=uid, **bad)
        assert r.status_code == 400, bad
        assert r.json()["error"] == "Expiry must be a valid timestamp in the future"

    r = await _set_expiry(ds, cookies, id="ghost", in_days=30)
    assert r.status_code == 404
    assert r.json()["error"] == "Unknown account"


@pytest.mark.asyncio
async def test_set_expiry_api_normalizes_offsets_to_utc():
    ds = await make_ds()
    cookies, uid = await _admin_and_target(ds)
    r = await _set_expiry(ds, cookies, id=uid, expires_at="2099-01-02T03:04:05+02:00")
    assert r.status_code == 200
    assert r.json() == {"ok": True, "expires_at": "2099-01-02T01:04:05.000+00:00"}
    internal = ds.get_internal_database()
    user = await db.get_user_by_id(internal, uid)
    assert user["expires_at"] == "2099-01-02T01:04:05.000+00:00"


@pytest.mark.asyncio
async def test_set_expiry_api_last_admin_409_and_clear():
    ds = await make_ds()
    cookies, uid = await _admin_and_target(ds)
    internal = ds.get_internal_database()
    admin = await db.get_user_by_username(internal, "admin")

    # Putting a fuse on the only enabled admin is refused.
    r = await _set_expiry(ds, cookies, id=admin["id"], in_days=30)
    assert r.status_code == 409
    assert r.json()["error"] == "Cannot set an expiry on the last admin"

    # Set on a plain account, then clear (no value forms) — clears + audits.
    r = await _set_expiry(ds, cookies, id=uid, in_days=30)
    assert r.status_code == 200
    r = await _set_expiry(ds, cookies, id=uid)
    assert r.status_code == 200
    assert r.json() == {"ok": True, "expires_at": None}
    user = await db.get_user_by_id(internal, uid)
    assert user["expires_at"] is None
    audit = await db.list_admin_audit(internal, target_id=uid, limit=2)
    assert [a["operation"] for a in audit] == ["clear-expiry", "set-expiry"]


@pytest.mark.asyncio
async def test_expiry_set_via_api_blocks_login_end_to_end():
    """The full chain: an admin sets a deadline through the API (proving the
    API → storage path), the stored deadline is then moved into the past
    (directly, like test_live_session_dies_once_expiry_passes — no sleeping
    through a real clock), and ticket 1's enforcement refuses the login with
    the "expired" audit reason.
    """
    ds = await make_ds()
    cookies, uid = await _admin_and_target(ds)
    internal = ds.get_internal_database()

    r = await _set_expiry(ds, cookies, id=uid, in_days=30)
    assert r.status_code == 200
    stored = r.json()["expires_at"]
    assert stored is not None
    assert (await db.get_user_by_id(internal, uid))["expires_at"] == stored

    # The deadline "passes": rewrite the stored value into the past. The API
    # itself can never set a past deadline (normalizeFutureTimestamp), which
    # is exactly why the clock is advanced this way.
    await internal.execute_write(
        f"UPDATE {db.USERS} SET expires_at = ? WHERE id = ?", [PAST, uid]
    )

    r, session = await login(ds, "temp", "password123")
    assert r.status_code == 401
    assert not session
    reason = (
        await internal.execute(
            f"SELECT reason FROM {db.LOGIN_AUDIT} ORDER BY id DESC LIMIT 1"
        )
    ).single_value()
    assert reason == "expired"


# --------------------------------------------------------------------------
# Admin audit-trail page + API
# --------------------------------------------------------------------------


def _page_data(html):
    """Extract the #pageData JSON embedded in a rendered page shell."""
    marker = '<script type="application/json" id="pageData">'
    start = html.index(marker) + len(marker)
    end = html.index("</script>", start)
    return json.loads(html[start:end])


@pytest.mark.asyncio
async def test_admin_audit_page_requires_admin():
    ds = await make_ds()
    await insert_user(ds, "bob")
    _, cookies = await login(ds, "bob", "password123")
    r = await ds.client.get("/-/admin/audit", cookies=cookies)
    assert r.status_code == 403


@pytest.mark.asyncio
async def test_admin_page_anonymous_redirects_to_login():
    # No session at all → almost certainly an admin whose session expired,
    # so bounce to the login page with ?next= back to the requested page
    # (query string included). A signed-in non-admin still 403s (above).
    ds = await make_ds()
    r = await ds.client.get("/-/admin/audit?username=alice")
    assert r.status_code == 302
    assert (
        r.headers["location"]
        == "/-/login?next=%2F-%2Fadmin%2Faudit%3Fusername%3Dalice"
    )


@pytest.mark.asyncio
async def test_admin_audit_page_prefilters_from_query_string():
    ds = await make_ds()
    admin_id = await insert_user(ds, "admin", is_admin=True)
    internal = ds.get_internal_database()
    alice_id = await db.create_user(
        internal, admin_id, "alice", hash_password("password123"), False, False
    )
    bob_id = await db.create_user(
        internal, admin_id, "bob", hash_password("password123"), False, False
    )
    await db.disable_user(internal, admin_id, alice_id)

    _, cookies = await login(ds, "admin", "password123")
    r = await ds.client.get(
        "/-/admin/audit?username=alice&operation=disable", cookies=cookies
    )
    assert r.status_code == 200
    data = _page_data(r.text)
    assert data["filter_username"] == "alice"
    assert data["filter_operation"] == "disable"
    assert [e["operation"] for e in data["entries"]] == ["disable"]
    assert data["entries"][0]["target_id"] == alice_id
    assert data["entries"][0]["target_username"] == "alice"
    assert data["entries"][0]["actor_username"] == "admin"
    # The operations dropdown reflects the data, distinct + sorted.
    assert data["operations"] == ["create", "disable"]

    # Unfiltered: every entry, newest first.
    r = await ds.client.get("/-/admin/audit", cookies=cookies)
    data = _page_data(r.text)
    assert data["filter_username"] == ""
    assert data["filter_operation"] == ""
    assert [e["target_id"] for e in data["entries"]] == [alice_id, bob_id, alice_id]


@pytest.mark.asyncio
async def test_admin_audit_api_filters_and_combine():
    ds = await make_ds()
    admin_id = await insert_user(ds, "admin", is_admin=True)
    internal = ds.get_internal_database()
    alice_id = await db.create_user(
        internal, admin_id, "alice", hash_password("password123"), False, False
    )
    bob_id = await db.create_user(
        internal, admin_id, "bob", hash_password("password123"), False, False
    )
    await db.disable_user(internal, admin_id, alice_id)
    await db.disable_user(internal, admin_id, bob_id)

    _, cookies = await login(ds, "admin", "password123")

    async def query(body):
        r = await ds.client.post(
            "/-/admin/api/audit",
            content=json.dumps(body),
            headers=JSON,
            cookies=cookies,
        )
        assert r.status_code == 200
        data = r.json()
        assert data["ok"]
        return data["entries"]

    # Username alone (resolved server-side to alice's id).
    entries = await query({"username": "alice"})
    assert {e["operation"] for e in entries} == {"create", "disable"}
    assert all(e["target_id"] == alice_id for e in entries)

    # Operation alone.
    entries = await query({"operation": "disable"})
    assert {e["target_id"] for e in entries} == {alice_id, bob_id}

    # AND-combined.
    entries = await query({"username": "alice", "operation": "disable"})
    assert len(entries) == 1
    assert entries[0]["target_id"] == alice_id
    assert entries[0]["operation"] == "disable"


@pytest.mark.asyncio
async def test_admin_audit_api_unknown_username_yields_empty():
    ds = await make_ds()
    await insert_user(ds, "admin", is_admin=True)
    _, cookies = await login(ds, "admin", "password123")
    r = await ds.client.post(
        "/-/admin/api/audit",
        content=json.dumps({"username": "nobody"}),
        headers=JSON,
        cookies=cookies,
    )
    assert r.status_code == 200
    assert r.json() == {"ok": True, "entries": []}


@pytest.mark.asyncio
async def test_admin_audit_api_requires_admin():
    ds = await make_ds()
    await insert_user(ds, "bob")
    _, cookies = await login(ds, "bob", "password123")
    r = await ds.client.post(
        "/-/admin/api/audit", content="{}", headers=JSON, cookies=cookies
    )
    assert r.status_code == 403


# --------------------------------------------------------------------------
# M6 — user-profiles seeding (skips if user-profiles is not installed)
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_user_profiles_seeding():
    pytest.importorskip("datasette_user_profiles")
    from datasette_user_profiles.seed import apply_seeds

    ds = await make_ds()
    uid = await insert_user(ds, "alice")
    await apply_seeds(ds)
    internal = ds.get_internal_database()
    rows = (await internal.execute("SELECT actor_id FROM datasette_user_profiles")).rows
    assert uid in [r[0] for r in rows]


# --------------------------------------------------------------------------
# Session list ticket 1 — "Your sessions" on the account page (read-only)
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_account_page_lists_own_sessions_with_one_current():
    ds = await make_ds()
    await insert_user(ds, "alice")
    _, cookies1 = await login(ds, "alice", "password123")
    _, cookies2 = await login(ds, "alice", "password123")
    r = await ds.client.get("/-/account", cookies=cookies2)
    assert r.status_code == 200
    page_data = extract_page_data(r.text)
    sessions = page_data["sessions"]
    assert len(sessions) == 2
    current_rows = [s for s in sessions if s["current"]]
    assert len(current_rows) == 1
    expected_sha = token_sha256(ds.unsign(cookies2[COOKIE_NAME], SIGN_NAMESPACE))
    assert current_rows[0]["token_sha256"] == expected_sha
    # Most-recent last_seen_at first.
    assert sessions[0]["last_seen_at"] >= sessions[1]["last_seen_at"]
    # cookies1 never gets referenced beyond minting a second session for alice.
    assert cookies1 != cookies2


@pytest.mark.asyncio
async def test_account_page_omits_sessions_during_forced_change():
    ds = await make_ds()
    await insert_user(ds, "alice", must_change_password=True)
    _, cookies = await login(ds, "alice", "password123")
    r = await ds.client.get("/-/account", cookies=cookies)
    assert r.status_code == 200
    page_data = extract_page_data(r.text)
    assert page_data["must_change_password"] is True
    assert page_data["sessions"] == []


@pytest.mark.asyncio
async def test_account_sessions_api_requires_actor():
    ds = await make_ds()
    r = await ds.client.post("/-/account/api/sessions", content="{}", headers=JSON)
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_account_sessions_api_enforces_csrf_and_post_only():
    ds = await make_ds()
    await insert_user(ds, "alice")
    _, cookies = await login(ds, "alice", "password123")
    # GET is rejected outright (method-not-allowed).
    r = await ds.client.get("/-/account/api/sessions", cookies=cookies)
    assert r.status_code == 405
    # A non-JSON content type fails the CSRF gate.
    r = await ds.client.post(
        "/-/account/api/sessions",
        content="{}",
        headers={"content-type": "text/plain"},
        cookies=cookies,
    )
    assert r.status_code == 403


@pytest.mark.asyncio
async def test_account_sessions_api_scopes_to_caller():
    ds = await make_ds()
    await insert_user(ds, "alice")
    await insert_user(ds, "bob")
    await login(ds, "alice", "password123")
    _, bob_cookies = await login(ds, "bob", "password123")
    r = await ds.client.post(
        "/-/account/api/sessions", content="{}", headers=JSON, cookies=bob_cookies
    )
    assert r.status_code == 200
    data = r.json()
    assert data["ok"] is True
    # bob only ever sees his own session, never alice's.
    assert len(data["sessions"]) == 1
    expected_sha = token_sha256(ds.unsign(bob_cookies[COOKIE_NAME], SIGN_NAMESPACE))
    assert data["sessions"][0]["token_sha256"] == expected_sha
    assert data["sessions"][0]["current"] is True


@pytest.mark.asyncio
async def test_account_sessions_null_ua_ip_render_as_none():
    ds = await make_ds()
    user_id = await insert_user(ds, "alice")
    internal = ds.get_internal_database()
    # A session recorded with no user-agent/IP (e.g. a non-browser client)
    # must not break row assembly.
    await db.create_session(internal, user_id, "deadbeef" * 8, 14, None, None)
    _, cookies = await login(ds, "alice", "password123")
    r = await ds.client.post(
        "/-/account/api/sessions", content="{}", headers=JSON, cookies=cookies
    )
    assert r.status_code == 200
    sessions = r.json()["sessions"]
    assert len(sessions) == 2
    null_row = next(s for s in sessions if s["token_sha256"] == "deadbeef" * 8)
    assert null_row["user_agent"] is None
    assert null_row["ip"] is None


# --------------------------------------------------------------------------
# Session list ticket 2 — revoke own sessions + log out everywhere else
# --------------------------------------------------------------------------


def cookie_sha(ds, cookies):
    """The sessions-table hash for a login cookie."""
    return token_sha256(ds.unsign(cookies[COOKIE_NAME], SIGN_NAMESPACE))


async def actor_resolves(ds, cookies):
    who = await ds.client.get("/-/actor.json", cookies=cookies)
    return who.json()["actor"] is not None


async def last_audit_row(ds, operation):
    internal = ds.get_internal_database()
    rows = await internal.execute(
        f"SELECT actor_id, target_id FROM {db.ADMIN_AUDIT} "
        "WHERE operation = ? ORDER BY id DESC LIMIT 1",
        [operation],
    )
    return rows.first()


@pytest.mark.asyncio
async def test_revoke_own_session_kills_it_and_audits():
    ds = await make_ds()
    alice_id = await insert_user(ds, "alice")
    _, cookies1 = await login(ds, "alice", "password123")
    _, cookies2 = await login(ds, "alice", "password123")
    r = await ds.client.post(
        "/-/account/api/revoke-session",
        content=json.dumps({"token_sha256": cookie_sha(ds, cookies1)}),
        headers=JSON,
        cookies=cookies2,
    )
    assert r.status_code == 200 and r.json()["ok"] is True
    # The revoked cookie stops resolving; the caller's stays alive.
    assert not await actor_resolves(ds, cookies1)
    assert await actor_resolves(ds, cookies2)
    audit = await last_audit_row(ds, "revoke-session")
    assert audit is not None
    assert (audit["actor_id"], audit["target_id"]) == (alice_id, alice_id)


@pytest.mark.asyncio
async def test_revoke_current_session_rejected():
    ds = await make_ds()
    await insert_user(ds, "alice")
    _, cookies = await login(ds, "alice", "password123")
    r = await ds.client.post(
        "/-/account/api/revoke-session",
        content=json.dumps({"token_sha256": cookie_sha(ds, cookies)}),
        headers=JSON,
        cookies=cookies,
    )
    assert r.status_code == 400
    assert "log out" in r.json()["error"].lower()
    # The current session survives.
    assert await actor_resolves(ds, cookies)


@pytest.mark.asyncio
async def test_revoke_foreign_token_is_scoped_noop():
    ds = await make_ds()
    alice_id = await insert_user(ds, "alice")
    await insert_user(ds, "bob")
    _, alice_cookies = await login(ds, "alice", "password123")
    _, bob_cookies = await login(ds, "bob", "password123")
    r = await ds.client.post(
        "/-/account/api/revoke-session",
        content=json.dumps({"token_sha256": cookie_sha(ds, alice_cookies)}),
        headers=JSON,
        cookies=bob_cookies,
    )
    # ok either way — a distinguishing response would be an existence oracle
    # for other accounts' token hashes.
    assert r.status_code == 200 and r.json()["ok"] is True
    # Alice's session survives: the DELETE is scoped to the caller's actor id.
    assert await actor_resolves(ds, alice_cookies)
    internal = ds.get_internal_database()
    count = (
        await internal.execute(
            f"SELECT COUNT(*) FROM {db.SESSIONS} WHERE actor_id = ?", [alice_id]
        )
    ).single_value()
    assert count == 1


@pytest.mark.asyncio
async def test_logout_others_keeps_current_session():
    ds = await make_ds()
    alice_id = await insert_user(ds, "alice")
    _, cookies1 = await login(ds, "alice", "password123")
    _, cookies2 = await login(ds, "alice", "password123")
    _, cookies3 = await login(ds, "alice", "password123")
    r = await ds.client.post(
        "/-/account/api/logout-others", content="{}", headers=JSON, cookies=cookies3
    )
    assert r.status_code == 200 and r.json()["ok"] is True
    # The calling session stays signed in; both others are dead.
    assert await actor_resolves(ds, cookies3)
    assert not await actor_resolves(ds, cookies1)
    assert not await actor_resolves(ds, cookies2)
    audit = await last_audit_row(ds, "logout-others")
    assert audit is not None
    assert (audit["actor_id"], audit["target_id"]) == (alice_id, alice_id)


@pytest.mark.asyncio
async def test_session_mutations_require_actor_and_gates():
    ds = await make_ds()
    await insert_user(ds, "alice")
    _, cookies = await login(ds, "alice", "password123")
    revoke_body = json.dumps({"token_sha256": "0" * 64})

    # Anonymous -> 401 (CSRF-clean POSTs, no cookie).
    r = await ds.client.post(
        "/-/account/api/revoke-session", content=revoke_body, headers=JSON
    )
    assert r.status_code == 401
    r = await ds.client.post("/-/account/api/logout-others", content="{}", headers=JSON)
    assert r.status_code == 401

    # GET never mutates: 405 from the POST-only gate (revoke-session needs a
    # valid body to get past router body-parsing and reach the gate).
    r = await ds.client.request(
        "GET",
        "/-/account/api/revoke-session",
        content=revoke_body,
        headers=JSON,
        cookies=cookies,
    )
    assert r.status_code == 405
    r = await ds.client.get("/-/account/api/logout-others", cookies=cookies)
    assert r.status_code == 405

    # Non-JSON content type fails the CSRF gate.
    for path, body in [
        ("/-/account/api/revoke-session", revoke_body),
        ("/-/account/api/logout-others", "{}"),
    ]:
        r = await ds.client.post(
            path, content=body, headers={"content-type": "text/plain"}, cookies=cookies
        )
        assert r.status_code == 403, path

    # The signed-in session is untouched by all of the above.
    assert await actor_resolves(ds, cookies)
