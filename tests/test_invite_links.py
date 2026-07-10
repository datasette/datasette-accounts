"""Invite-link tracer: admin mints a link -> user sets a password -> signed in.

See plans/invite-links/{plan,tickets}.md. Reset links + admin-UI integration
are later tickets and are not exercised here.
"""

import json
import re

import pytest
from datasette.app import Datasette

from datasette_accounts import db
from datasette_accounts.passwords import hash_password
from datasette_accounts.security import COOKIE_NAME
from datasette_accounts.sessions import mint_token, token_sha256

JSON = {"content-type": "application/json"}

PAGE_DATA_RE = re.compile(
    r'<script type="application/json" id="pageData">(.*?)</script>', re.S
)


async def make_ds(**plugin_config):
    metadata = {}
    if plugin_config:
        metadata = {"plugins": {"datasette-accounts": plugin_config}}
    ds = Datasette(memory=True, metadata=metadata)
    await ds.invoke_startup()
    return ds


async def insert_user(
    ds, username, password="password123", is_admin=False, disabled=False
):
    internal = ds.get_internal_database()
    user_id = db.new_id()
    ts = db.now_iso()
    await internal.execute_write(
        f"INSERT INTO {db.USERS} (id, username, password_hash, is_admin, disabled, "
        "must_change_password, failed_attempts, locked_until, created_at, updated_at) "
        "VALUES (?, ?, ?, ?, ?, 0, 0, NULL, ?, ?)",
        [
            user_id,
            username,
            hash_password(password),
            1 if is_admin else 0,
            1 if disabled else 0,
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


async def session_cookie(ds, actor_id):
    internal = ds.get_internal_database()
    raw = mint_token()
    await db.create_session(internal, actor_id, token_sha256(raw), 14, "ua", "1.1.1.1")
    from datasette_accounts.security import SIGN_NAMESPACE

    return {COOKIE_NAME: ds.sign(raw, SIGN_NAMESPACE)}


def page_data(resp):
    m = PAGE_DATA_RE.search(resp.text)
    assert m, "no #pageData script tag found"
    return json.loads(m.group(1))


def token_from_url(url):
    m = re.search(r"[?&]token=([^&]+)", url)
    assert m, f"no token in url: {url}"
    return m.group(1)


# --------------------------------------------------------------------------
# Admin invite API
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_admin_invite_creates_account_and_returns_url_once():
    ds = await make_ds()
    admin_id = await insert_user(ds, "admin", is_admin=True)
    cookies = await session_cookie(ds, admin_id)

    r = await ds.client.post(
        "/-/admin/api/invite",
        content=json.dumps({"username": "carol"}),
        headers=JSON,
        cookies=cookies,
    )
    assert r.status_code == 200
    body = r.json()
    assert body["ok"] is True
    assert body["id"]
    assert body["url"] and "/-/set-password?token=" in body["url"]
    # Absolute (has a scheme + host), not just a path.
    assert body["url"].startswith("http")

    internal = ds.get_internal_database()
    user = await db.get_user_by_id(internal, body["id"])
    assert user["username"] == "carol"
    from datasette_accounts.passwords import UNUSABLE_PASSWORD

    assert user["password_hash"] == UNUSABLE_PASSWORD

    audit = await internal.execute(
        f"SELECT operation FROM {db.ADMIN_AUDIT} WHERE target_id = ?", [body["id"]]
    )
    assert [r[0] for r in audit.rows] == ["invite"]


@pytest.mark.asyncio
async def test_admin_invite_duplicate_username_409():
    ds = await make_ds()
    admin_id = await insert_user(ds, "admin", is_admin=True)
    await insert_user(ds, "carol")
    cookies = await session_cookie(ds, admin_id)

    r = await ds.client.post(
        "/-/admin/api/invite",
        content=json.dumps({"username": "carol"}),
        headers=JSON,
        cookies=cookies,
    )
    assert r.status_code == 409
    assert r.json() == {"ok": False, "error": "Username already taken"}


@pytest.mark.asyncio
async def test_admin_invite_requires_admin():
    ds = await make_ds()
    bob_id = await insert_user(ds, "bob")
    cookies = await session_cookie(ds, bob_id)

    r = await ds.client.post(
        "/-/admin/api/invite",
        content=json.dumps({"username": "new-user"}),
        headers=JSON,
        cookies=cookies,
    )
    assert r.status_code == 403


@pytest.mark.asyncio
async def test_admin_invite_link_requires_admin():
    ds = await make_ds()
    bob_id = await insert_user(ds, "bob")
    cookies = await session_cookie(ds, bob_id)

    r = await ds.client.post(
        "/-/admin/api/invite-link",
        content=json.dumps({"id": bob_id}),
        headers=JSON,
        cookies=cookies,
    )
    assert r.status_code == 403


@pytest.mark.asyncio
async def test_invite_and_invite_link_endpoints_405_on_get():
    # datasette-plugin-router does not dispatch by HTTP method, and it parses
    # a Body-annotated handler's request body *before* our decorator's
    # method gate runs — so the body must still validate for the request to
    # reach the gate and get a genuine 405 (rather than a body-validation 400).
    ds = await make_ds()
    admin_id = await insert_user(ds, "admin", is_admin=True)
    cookies = await session_cookie(ds, admin_id)

    bodies = {
        "/-/admin/api/invite": {"username": "whoever"},
        "/-/admin/api/invite-link": {"id": "whoever"},
    }
    for path, body in bodies.items():
        r = await ds.client.request(
            "GET", path, content=json.dumps(body), headers=JSON, cookies=cookies
        )
        assert r.status_code == 405, path


@pytest.mark.asyncio
async def test_set_password_complete_405_on_get():
    ds = await make_ds()
    r = await ds.client.request(
        "GET",
        "/-/set-password/api/complete",
        content=json.dumps({"token": "x", "new_password": "whatever-pass1"}),
        headers=JSON,
    )
    assert r.status_code == 405


# --------------------------------------------------------------------------
# GET /-/set-password
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_set_password_page_valid_token_shows_username_and_purpose():
    ds = await make_ds()
    admin_id = await insert_user(ds, "admin", is_admin=True)
    cookies = await session_cookie(ds, admin_id)
    invite = (
        await ds.client.post(
            "/-/admin/api/invite",
            content=json.dumps({"username": "dave"}),
            headers=JSON,
            cookies=cookies,
        )
    ).json()
    token = token_from_url(invite["url"])

    r = await ds.client.get(f"/-/set-password?token={token}")
    assert r.status_code == 200
    data = page_data(r)
    assert data == {
        "valid": True,
        "purpose": "invite",
        "username": "dave",
        "token": token,
    }


@pytest.mark.asyncio
async def test_set_password_page_invalid_token_is_generic_and_audited():
    ds = await make_ds()
    r = await ds.client.get("/-/set-password?token=not-a-real-token")
    assert r.status_code == 200
    data = page_data(r)
    assert data == {"valid": False, "purpose": "", "username": "", "token": ""}

    internal = ds.get_internal_database()
    row = (
        await internal.execute(
            f"SELECT reason, username FROM {db.LOGIN_AUDIT} ORDER BY id DESC LIMIT 1"
        )
    ).rows[0]
    assert row[0] == "bad_token"
    assert row[1] is None


@pytest.mark.asyncio
async def test_set_password_page_missing_token_is_generic_and_audited():
    ds = await make_ds()
    r = await ds.client.get("/-/set-password")
    assert r.status_code == 200
    data = page_data(r)
    assert data["valid"] is False

    internal = ds.get_internal_database()
    reason = (
        await internal.execute(
            f"SELECT reason FROM {db.LOGIN_AUDIT} ORDER BY id DESC LIMIT 1"
        )
    ).single_value()
    assert reason == "bad_token"


# --------------------------------------------------------------------------
# POST /-/set-password/api/complete
# --------------------------------------------------------------------------


async def _invite(ds, cookies, username):
    r = await ds.client.post(
        "/-/admin/api/invite",
        content=json.dumps({"username": username}),
        headers=JSON,
        cookies=cookies,
    )
    body = r.json()
    return body["id"], token_from_url(body["url"])


@pytest.mark.asyncio
async def test_complete_sets_password_signs_in_and_redirects():
    ds = await make_ds()
    admin_id = await insert_user(ds, "admin", is_admin=True)
    admin_cookies = await session_cookie(ds, admin_id)
    user_id, token = await _invite(ds, admin_cookies, "erin")

    r = await ds.client.post(
        "/-/set-password/api/complete",
        content=json.dumps({"token": token, "new_password": "brand-new-pass1"}),
        headers=JSON,
    )
    assert r.status_code == 200
    body = r.json()
    assert body == {"ok": True, "redirect": "/"}
    cookie = r.cookies.get(COOKIE_NAME)
    assert cookie

    # The cookie resolves a real, signed-in actor on a subsequent request.
    who = await ds.client.get("/-/actor.json", cookies={COOKIE_NAME: cookie})
    assert who.json()["actor"]["username"] == "erin"

    # The new password actually authenticates.
    login_r, _ = await login(ds, "erin", "brand-new-pass1")
    assert login_r.json()["ok"] is True


@pytest.mark.asyncio
async def test_complete_second_use_fails_generically():
    ds = await make_ds()
    admin_id = await insert_user(ds, "admin", is_admin=True)
    admin_cookies = await session_cookie(ds, admin_id)
    user_id, token = await _invite(ds, admin_cookies, "frank")

    first = await ds.client.post(
        "/-/set-password/api/complete",
        content=json.dumps({"token": token, "new_password": "first-password1"}),
        headers=JSON,
    )
    assert first.status_code == 200

    second = await ds.client.post(
        "/-/set-password/api/complete",
        content=json.dumps({"token": token, "new_password": "second-password1"}),
        headers=JSON,
    )
    assert second.status_code == 400
    assert second.json() == {
        "ok": False,
        "error": "This link is invalid or has expired",
    }

    internal = ds.get_internal_database()
    reason = (
        await internal.execute(
            f"SELECT reason FROM {db.LOGIN_AUDIT} ORDER BY id DESC LIMIT 1"
        )
    ).single_value()
    assert reason == "bad_token"

    # The first password still works; the second attempt never took.
    login_r, _ = await login(ds, "frank", "first-password1")
    assert login_r.json()["ok"] is True


@pytest.mark.asyncio
async def test_complete_short_password_400_and_token_not_consumed():
    """The length check MUST precede the token claim: a typo'd (too-short)
    password must not burn the single-use link."""
    ds = await make_ds()
    admin_id = await insert_user(ds, "admin", is_admin=True)
    admin_cookies = await session_cookie(ds, admin_id)
    user_id, token = await _invite(ds, admin_cookies, "gina")

    short = await ds.client.post(
        "/-/set-password/api/complete",
        content=json.dumps({"token": token, "new_password": "short"}),
        headers=JSON,
    )
    assert short.status_code == 400
    assert not short.cookies.get(COOKIE_NAME)

    # The token is still live: the page still renders it as valid...
    page = await ds.client.get(f"/-/set-password?token={token}")
    assert page_data(page)["valid"] is True

    # ...and a proper-length password now completes it successfully.
    ok = await ds.client.post(
        "/-/set-password/api/complete",
        content=json.dumps({"token": token, "new_password": "long-enough-pass1"}),
        headers=JSON,
    )
    assert ok.status_code == 200
    assert ok.json()["ok"] is True


@pytest.mark.asyncio
async def test_complete_against_disabled_account_sets_password_but_no_session():
    ds = await make_ds()
    admin_id = await insert_user(ds, "admin", is_admin=True)
    admin_cookies = await session_cookie(ds, admin_id)
    user_id, token = await _invite(ds, admin_cookies, "harry")

    # Disable directly (not via the admin API, which would also purge the
    # outstanding token) to simulate the account going disabled while the
    # link is still outstanding.
    internal = ds.get_internal_database()
    await internal.execute_write(
        f"UPDATE {db.USERS} SET disabled = 1 WHERE id = ?", [user_id]
    )

    r = await ds.client.post(
        "/-/set-password/api/complete",
        content=json.dumps({"token": token, "new_password": "new-password-1"}),
        headers=JSON,
    )
    assert r.status_code == 200
    assert r.json() == {"ok": True, "redirect": "/-/login"}
    assert not r.cookies.get(COOKIE_NAME)

    user = await db.get_user_by_id(internal, user_id)
    from datasette_accounts.passwords import verify_password

    assert verify_password("new-password-1", user["password_hash"])

    # No session was created for the account.
    count = (
        await internal.execute(
            f"SELECT COUNT(*) FROM {db.SESSIONS} WHERE actor_id = ?", [user_id]
        )
    ).single_value()
    assert count == 0


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "column,value",
    [
        ("expires_at", "2000-01-01T00:00:00.000+00:00"),
        ("pending_approval", 1),
    ],
)
async def test_complete_against_expired_or_pending_account_no_session(column, value):
    # Completion mirrors authenticate(): an expired or still-pending account
    # gets its password set (the link proved control) but is never signed in —
    # otherwise the minted session would outlive the blocked state (e.g. come
    # back to life when an admin later clears the expiry).
    ds = await make_ds()
    admin_id = await insert_user(ds, "admin", is_admin=True)
    admin_cookies = await session_cookie(ds, admin_id)
    user_id, token = await _invite(ds, admin_cookies, "iris")

    # Flip the state directly to simulate it changing while the link is
    # still outstanding (same pattern as the disabled test above).
    internal = ds.get_internal_database()
    await internal.execute_write(
        f"UPDATE {db.USERS} SET {column} = ? WHERE id = ?", [value, user_id]
    )

    r = await ds.client.post(
        "/-/set-password/api/complete",
        content=json.dumps({"token": token, "new_password": "new-password-1"}),
        headers=JSON,
    )
    assert r.status_code == 200
    assert r.json() == {"ok": True, "redirect": "/-/login"}
    assert not r.cookies.get(COOKIE_NAME)

    user = await db.get_user_by_id(internal, user_id)
    from datasette_accounts.passwords import verify_password

    assert verify_password("new-password-1", user["password_hash"])

    # No session was created, and the account still cannot log in.
    count = (
        await internal.execute(
            f"SELECT COUNT(*) FROM {db.SESSIONS} WHERE actor_id = ?", [user_id]
        )
    ).single_value()
    assert count == 0
    login_r, _ = await login(ds, "iris", "new-password-1")
    assert login_r.status_code == 401


# --------------------------------------------------------------------------
# Re-minting (admin/api/invite-link)
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_invite_link_remint_invalidates_prior_link():
    ds = await make_ds()
    admin_id = await insert_user(ds, "admin", is_admin=True)
    admin_cookies = await session_cookie(ds, admin_id)
    user_id, old_token = await _invite(ds, admin_cookies, "ivy")

    remint = await ds.client.post(
        "/-/admin/api/invite-link",
        content=json.dumps({"id": user_id}),
        headers=JSON,
        cookies=admin_cookies,
    )
    assert remint.status_code == 200
    remint_body = remint.json()
    assert remint_body["ok"] is True
    new_token = token_from_url(remint_body["url"])
    assert new_token != old_token

    # The old link is dead end-to-end.
    old_attempt = await ds.client.post(
        "/-/set-password/api/complete",
        content=json.dumps({"token": old_token, "new_password": "whatever-pass1"}),
        headers=JSON,
    )
    assert old_attempt.status_code == 400

    # The new link works.
    new_attempt = await ds.client.post(
        "/-/set-password/api/complete",
        content=json.dumps({"token": new_token, "new_password": "whatever-pass1"}),
        headers=JSON,
    )
    assert new_attempt.status_code == 200
    assert new_attempt.json()["ok"] is True


# --------------------------------------------------------------------------
# Reset links for existing accounts (admin/api/reset-link)
# --------------------------------------------------------------------------


async def _reset_link(ds, cookies, target_id):
    r = await ds.client.post(
        "/-/admin/api/reset-link",
        content=json.dumps({"id": target_id}),
        headers=JSON,
        cookies=cookies,
    )
    return r


@pytest.mark.asyncio
async def test_reset_link_minting_does_not_revoke_sessions():
    ds = await make_ds()
    admin_id = await insert_user(ds, "admin", is_admin=True)
    admin_cookies = await session_cookie(ds, admin_id)
    await insert_user(ds, "kate")
    _, kate_cookies = await login(ds, "kate", "password123")

    r = await _reset_link(
        ds,
        admin_cookies,
        (await db.get_user_by_username(ds.get_internal_database(), "kate"))["id"],
    )
    assert r.status_code == 200
    body = r.json()
    assert body["ok"] is True
    assert body["url"] and "/-/set-password?token=" in body["url"]
    assert body["url"].startswith("http")

    # Kate stays signed in until the link is actually used.
    who = await ds.client.get("/-/actor.json", cookies=kate_cookies)
    assert who.json()["actor"]["username"] == "kate"

    internal = ds.get_internal_database()
    audit = await internal.execute(
        f"SELECT operation FROM {db.ADMIN_AUDIT} ORDER BY id DESC LIMIT 1"
    )
    assert audit.single_value() == "mint-reset-link"


@pytest.mark.asyncio
async def test_reset_token_page_shows_reset_purpose():
    ds = await make_ds()
    admin_id = await insert_user(ds, "admin", is_admin=True)
    admin_cookies = await session_cookie(ds, admin_id)
    kate_id = await insert_user(ds, "kate")

    r = await _reset_link(ds, admin_cookies, kate_id)
    token = token_from_url(r.json()["url"])

    page = await ds.client.get(f"/-/set-password?token={token}")
    assert page_data(page) == {
        "valid": True,
        "purpose": "reset",
        "username": "kate",
        "token": token,
    }


@pytest.mark.asyncio
async def test_complete_reset_sets_password_revokes_other_sessions_signs_in_fresh():
    ds = await make_ds()
    admin_id = await insert_user(ds, "admin", is_admin=True)
    admin_cookies = await session_cookie(ds, admin_id)
    kate_id = await insert_user(ds, "kate")
    # Two live sessions before the reset — both must die on completion.
    _, old_cookies_1 = await login(ds, "kate", "password123")
    _, old_cookies_2 = await login(ds, "kate", "password123")

    token = token_from_url(
        (await _reset_link(ds, admin_cookies, kate_id)).json()["url"]
    )

    r = await ds.client.post(
        "/-/set-password/api/complete",
        content=json.dumps({"token": token, "new_password": "fresh-password-1"}),
        headers=JSON,
    )
    assert r.status_code == 200
    assert r.json() == {"ok": True, "redirect": "/"}
    new_cookie = r.cookies.get(COOKIE_NAME)
    assert new_cookie

    # Every pre-existing session is revoked...
    for old in (old_cookies_1, old_cookies_2):
        who = await ds.client.get("/-/actor.json", cookies=old)
        assert who.json()["actor"] is None
    # ...but the fresh session minted by the completion works.
    who = await ds.client.get("/-/actor.json", cookies={COOKIE_NAME: new_cookie})
    assert who.json()["actor"]["username"] == "kate"

    # Old password dead, new password works.
    old_login, _ = await login(ds, "kate", "password123")
    assert old_login.status_code == 401
    new_login, _ = await login(ds, "kate", "fresh-password-1")
    assert new_login.json()["ok"] is True


@pytest.mark.asyncio
async def test_reset_link_requires_admin_and_post():
    ds = await make_ds()
    bob_id = await insert_user(ds, "bob")
    bob_cookies = await session_cookie(ds, bob_id)

    # Non-admin → 403.
    r = await _reset_link(ds, bob_cookies, bob_id)
    assert r.status_code == 403

    # GET (wrong method, valid body — see the invite 405 test) → 405.
    admin_id = await insert_user(ds, "admin", is_admin=True)
    admin_cookies = await session_cookie(ds, admin_id)
    r = await ds.client.request(
        "GET",
        "/-/admin/api/reset-link",
        content=json.dumps({"id": bob_id}),
        headers=JSON,
        cookies=admin_cookies,
    )
    assert r.status_code == 405


@pytest.mark.asyncio
async def test_mint_for_unknown_account_404_and_writes_nothing():
    # Minting checks the account exists inside the write transaction: a token
    # for a phantom user would still be claimable (the claim-by-delete doesn't
    # join users), producing a no-op password write + mis-attributed audit row.
    ds = await make_ds()
    admin_id = await insert_user(ds, "admin", is_admin=True)
    admin_cookies = await session_cookie(ds, admin_id)

    for path in ("/-/admin/api/reset-link", "/-/admin/api/invite-link"):
        r = await ds.client.post(
            path,
            content=json.dumps({"id": "no-such-user"}),
            headers=JSON,
            cookies=admin_cookies,
        )
        assert r.status_code == 404, path
        assert r.json() == {"ok": False, "error": "Unknown account"}, path

    internal = ds.get_internal_database()
    tokens = (
        await internal.execute(f"SELECT COUNT(*) FROM {db.PASSWORD_TOKENS}")
    ).single_value()
    assert tokens == 0
    audits = (
        await internal.execute(
            f"SELECT COUNT(*) FROM {db.ADMIN_AUDIT} WHERE operation LIKE 'mint-%'"
        )
    ).single_value()
    assert audits == 0


@pytest.mark.asyncio
async def test_admin_reset_password_kills_outstanding_reset_link():
    ds = await make_ds()
    admin_id = await insert_user(ds, "admin", is_admin=True)
    admin_cookies = await session_cookie(ds, admin_id)
    kate_id = await insert_user(ds, "kate")

    token = token_from_url(
        (await _reset_link(ds, admin_cookies, kate_id)).json()["url"]
    )

    # Admin resets the password out from under the outstanding link.
    r = await ds.client.post(
        "/-/admin/api/reset-password",
        content=json.dumps({"id": kate_id, "password": "admin-chosen-1"}),
        headers=JSON,
        cookies=admin_cookies,
    )
    assert r.status_code == 200

    # The link is dead end-to-end: page shows invalid, completion 400s.
    page = await ds.client.get(f"/-/set-password?token={token}")
    assert page_data(page)["valid"] is False
    attempt = await ds.client.post(
        "/-/set-password/api/complete",
        content=json.dumps({"token": token, "new_password": "link-chosen-pass1"}),
        headers=JSON,
    )
    assert attempt.status_code == 400
    # And the link's password never took — the admin-chosen one did.
    ok_login, _ = await login(ds, "kate", "admin-chosen-1")
    assert ok_login.json()["ok"] is True


# --------------------------------------------------------------------------
# Invited flag on the admin surfaces (list API + page data)
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_admin_surfaces_mark_invited_accounts():
    ds = await make_ds()
    admin_id = await insert_user(ds, "admin", is_admin=True)
    admin_cookies = await session_cookie(ds, admin_id)
    _, token = await _invite(ds, admin_cookies, "nia")

    async def flags():
        listed = await ds.client.post(
            "/-/admin/api/list", content="{}", headers=JSON, cookies=admin_cookies
        )
        api = {u["username"]: u["invited"] for u in listed.json()["users"]}
        page = await ds.client.get("/-/admin/users", cookies=admin_cookies)
        shell = {u["username"]: u["invited"] for u in page_data(page)["users"]}
        # The page shell and the refresh API assemble rows through the same
        # helper — they must always agree.
        assert api == shell
        return api

    invited = await flags()
    assert invited["nia"] is True
    assert invited["admin"] is False

    # Completing the invite clears the flag on both surfaces.
    r = await ds.client.post(
        "/-/set-password/api/complete",
        content=json.dumps({"token": token, "new_password": "chosen-by-nia-1"}),
        headers=JSON,
    )
    assert r.status_code == 200
    invited = await flags()
    assert invited["nia"] is False
