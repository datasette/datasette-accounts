"""Self-registration (plans/self-registration): a runtime toggle gates
/-/register; a visitor registers with their own password and lands in a
pending-approval queue that cannot log in or act until an admin approves.
Covers the tracer, the approval queue, the toggle/login page data, and the
abuse caps.
"""

import json
import re

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

    # Self-registration is now the password provider's signups policy (D5): the
    # toggle writes one audit vocabulary — set-provider-signups — with the mode
    # in the detail, superseding the retired enable/disable-registration ops.
    rows = (
        await internal.execute(
            f"SELECT operation, detail FROM {db.ADMIN_AUDIT} "
            "WHERE operation = 'set-provider-signups' ORDER BY id"
        )
    ).rows
    assert [r[0] for r in rows] == ["set-provider-signups", "set-provider-signups"]
    assert [json.loads(r[1]) for r in rows] == [
        {"provider": "password", "mode": "approval"},
        {"provider": "password", "mode": "off"},
    ]


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


# --------------------------------------------------------------------------
# Approval queue (ticket 2): approve / reject + admin UI data + banner
# --------------------------------------------------------------------------


async def register_pending(ds, username="newperson", password="password123"):
    """Toggle on (if needed), register, return the pending user row."""
    internal = ds.get_internal_database()
    await db.set_registration_enabled(internal, "root", True)
    r = await ds.client.post(
        "/-/register/api/submit",
        content=json.dumps({"username": username, "password": password}),
        headers=JSON,
    )
    assert r.status_code == 200
    return await db.get_user_by_username(internal, username)


@pytest.mark.asyncio
async def test_approve_flips_pending_and_account_can_log_in():
    ds = await make_ds()
    internal = ds.get_internal_database()
    await insert_user(ds, "boss", is_admin=True)
    _, cookies = await login(ds, "boss", "password123")
    user = await register_pending(ds)

    # Pending: login refuses.
    refused, _ = await login(ds, "newperson", "password123")
    assert refused.status_code == 401

    r = await ds.client.post(
        "/-/admin/api/approve",
        content=json.dumps({"id": user["id"]}),
        headers=JSON,
        cookies=cookies,
    )
    assert r.status_code == 200
    assert r.json() == {"ok": True}

    approved = await db.get_user_by_username(internal, "newperson")
    assert approved["pending_approval"] == 0

    audit = (
        await internal.execute(
            f"SELECT actor_id, target_id, detail FROM {db.ADMIN_AUDIT} "
            "WHERE operation = 'approve'"
        )
    ).rows
    assert len(audit) == 1
    assert audit[0][1] == user["id"]

    # End to end: the account can now sign in with the password it chose.
    signed_in, session = await login(ds, "newperson", "password123")
    assert signed_in.status_code == 200
    assert session


@pytest.mark.asyncio
async def test_reject_deletes_and_audits_username():
    ds = await make_ds()
    internal = ds.get_internal_database()
    await insert_user(ds, "boss", is_admin=True)
    _, cookies = await login(ds, "boss", "password123")
    user = await register_pending(ds)

    r = await ds.client.post(
        "/-/admin/api/reject",
        content=json.dumps({"id": user["id"]}),
        headers=JSON,
        cookies=cookies,
    )
    assert r.status_code == 200
    assert r.json() == {"ok": True}
    assert await db.get_user_by_username(internal, "newperson") is None

    # The row is gone, so the audit detail must keep the name findable.
    audit = (
        await internal.execute(
            f"SELECT target_id, detail FROM {db.ADMIN_AUDIT} WHERE operation = 'reject'"
        )
    ).rows
    assert len(audit) == 1
    assert audit[0][0] == user["id"]
    assert json.loads(audit[0][1])["username"] == "newperson"


@pytest.mark.asyncio
async def test_reject_non_pending_is_400_and_deletes_nothing():
    ds = await make_ds()
    internal = ds.get_internal_database()
    await insert_user(ds, "boss", is_admin=True)
    alice_id = await insert_user(ds, "alice")
    _, cookies = await login(ds, "boss", "password123")

    r = await ds.client.post(
        "/-/admin/api/reject",
        content=json.dumps({"id": alice_id}),
        headers=JSON,
        cookies=cookies,
    )
    assert r.status_code == 400
    assert r.json() == {"ok": False, "error": "Account is not awaiting approval"}
    # The mis-aimed reject deleted nothing.
    assert await db.get_user_by_username(internal, "alice") is not None


@pytest.mark.asyncio
async def test_approve_and_reject_unknown_account_404():
    ds = await make_ds()
    await insert_user(ds, "boss", is_admin=True)
    _, cookies = await login(ds, "boss", "password123")
    for path in ("/-/admin/api/approve", "/-/admin/api/reject"):
        r = await ds.client.post(
            path, content=json.dumps({"id": "ghost"}), headers=JSON, cookies=cookies
        )
        assert r.status_code == 404, path
        assert r.json() == {"ok": False, "error": "Unknown account"}


@pytest.mark.asyncio
async def test_approve_and_reject_require_admin():
    ds = await make_ds()
    await insert_user(ds, "alice")  # not an admin
    _, cookies = await login(ds, "alice", "password123")
    user = await register_pending(ds)
    for path in ("/-/admin/api/approve", "/-/admin/api/reject"):
        r = await ds.client.post(
            path,
            content=json.dumps({"id": user["id"]}),
            headers=JSON,
            cookies=cookies,
        )
        assert r.status_code == 403, path


@pytest.mark.asyncio
async def test_homepage_banner_shown_to_admin_while_queue_non_empty():
    ds = await make_ds()
    await insert_user(ds, "boss", is_admin=True)
    _, cookies = await login(ds, "boss", "password123")

    # Empty queue: no banner.
    r = await ds.client.get("/", cookies=cookies)
    assert "awaiting approval" not in r.text

    await register_pending(ds)
    r = await ds.client.get("/", cookies=cookies)
    assert "account request is awaiting approval" in r.text
    assert "/-/admin/users" in r.text

    # Pluralizes with more than one request.
    await register_pending(ds, username="another")
    r = await ds.client.get("/", cookies=cookies)
    assert "account requests are awaiting approval" in r.text


@pytest.mark.asyncio
async def test_homepage_banner_hidden_from_non_admins_and_anonymous():
    ds = await make_ds()
    await insert_user(ds, "alice")  # not an admin
    _, cookies = await login(ds, "alice", "password123")
    await register_pending(ds)

    signed_in = await ds.client.get("/", cookies=cookies)
    assert "awaiting approval" not in signed_in.text

    anonymous = await ds.client.get("/")
    assert "awaiting approval" not in anonymous.text


@pytest.mark.asyncio
async def test_admin_list_includes_pending_rows_with_flag():
    # The admin page/API must NOT hide pending accounts server-side — the UI
    # splits them into the "Awaiting approval" section using the flag.
    ds = await make_ds()
    await insert_user(ds, "boss", is_admin=True)
    _, cookies = await login(ds, "boss", "password123")
    await register_pending(ds)

    listed = await ds.client.post(
        "/-/admin/api/list", content="{}", headers=JSON, cookies=cookies
    )
    users = {u["username"]: u for u in listed.json()["users"]}
    assert users["newperson"]["pending_approval"] is True
    assert users["boss"]["pending_approval"] is False


# --------------------------------------------------------------------------
# Toggle UI + login-page entry point (ticket 3): page-data contracts
# --------------------------------------------------------------------------


def page_data_of(r):
    """Parse the embedded #pageData JSON out of a rendered page shell."""
    m = re.search(
        r'<script type="application/json" id="pageData">(.*?)</script>',
        r.text,
        re.S,
    )
    assert m, "no #pageData script tag in the page"
    return json.loads(m.group(1))


@pytest.mark.asyncio
async def test_config_page_data_carries_registration_state():
    ds = await make_ds()
    await insert_user(ds, "boss", is_admin=True)
    _, cookies = await login(ds, "boss", "password123")

    r = await ds.client.get("/-/admin/config", cookies=cookies)
    assert page_data_of(r)["registration_enabled"] is False

    on = await ds.client.post(
        "/-/admin/api/set-registration",
        content=json.dumps({"enabled": True}),
        headers=JSON,
        cookies=cookies,
    )
    assert on.status_code == 200

    r = await ds.client.get("/-/admin/config", cookies=cookies)
    assert page_data_of(r)["registration_enabled"] is True


@pytest.mark.asyncio
async def test_login_page_data_carries_allow_register():
    ds = await make_ds()
    await insert_user(ds, "boss", is_admin=True)
    _, cookies = await login(ds, "boss", "password123")

    r = await ds.client.get("/-/login")
    assert page_data_of(r)["allow_register"] is False

    # Flip via the admin API — the login page reflects it on the next request.
    await ds.client.post(
        "/-/admin/api/set-registration",
        content=json.dumps({"enabled": True}),
        headers=JSON,
        cookies=cookies,
    )
    r = await ds.client.get("/-/login")
    assert page_data_of(r)["allow_register"] is True

    await ds.client.post(
        "/-/admin/api/set-registration",
        content=json.dumps({"enabled": False}),
        headers=JSON,
        cookies=cookies,
    )
    r = await ds.client.get("/-/login")
    assert page_data_of(r)["allow_register"] is False


# --------------------------------------------------------------------------
# Abuse caps (ticket 4): per-IP daily cap + global pending-queue cap
# --------------------------------------------------------------------------

GENERIC_CLOSED = "Registration is currently closed — try again later."


async def submit(ds, username, ip=None, password="password123"):
    """POST a registration, optionally faking the client IP via X-Forwarded-For
    (only honoured when the ds was made with trust_proxy_headers=True)."""
    headers = dict(JSON)
    if ip:
        headers["x-forwarded-for"] = ip
    return await ds.client.post(
        "/-/register/api/submit",
        content=json.dumps({"username": username, "password": password}),
        headers=headers,
    )


@pytest.mark.asyncio
async def test_per_ip_cap_refuses_but_other_ips_unaffected():
    ds = await make_ds(trust_proxy_headers=True, registrations_per_ip_per_day=2)
    internal = ds.get_internal_database()
    await db.set_registration_enabled(internal, "root", True)

    # Under the cap: registrations from IP A are unaffected.
    assert (await submit(ds, "user1", ip="5.5.5.5")).status_code == 200
    assert (await submit(ds, "user2", ip="5.5.5.5")).status_code == 200

    # At the cap: the same IP is refused generically...
    r = await submit(ds, "user3", ip="5.5.5.5")
    assert r.status_code == 429
    assert r.json() == {"ok": False, "error": GENERIC_CLOSED}
    assert await db.get_user_by_username(internal, "user3") is None

    # ...and the refusal itself was recorded, so repeat abuse keeps counting
    # instead of probing for free.
    rows = (
        await internal.execute(
            f"SELECT success FROM {db.LOGIN_AUDIT} "
            "WHERE reason = 'register' AND ip = '5.5.5.5' ORDER BY id"
        )
    ).rows
    assert [row[0] for row in rows] == [1, 1, 0]

    # A different IP is unaffected (same username retries fine too — the
    # refused attempt never created an account).
    assert (await submit(ds, "user3", ip="6.6.6.6")).status_code == 200


@pytest.mark.asyncio
async def test_queue_cap_refuses_regardless_of_ip():
    ds = await make_ds(trust_proxy_headers=True, max_pending_registrations=1)
    internal = ds.get_internal_database()
    await db.set_registration_enabled(internal, "root", True)

    assert (await submit(ds, "user1", ip="1.2.3.4")).status_code == 200

    # A brand-new IP is still refused — the queue is full.
    r = await submit(ds, "user2", ip="9.8.7.6")
    assert r.status_code == 429
    assert r.json() == {"ok": False, "error": GENERIC_CLOSED}

    # Approving drains the queue and reopens registration.
    user = await db.get_user_by_username(internal, "user1")
    await db.approve_user(internal, "root", user["id"])
    assert (await submit(ds, "user2", ip="9.8.7.6")).status_code == 200


@pytest.mark.asyncio
async def test_both_caps_share_one_generic_message():
    per_ip_ds = await make_ds(trust_proxy_headers=True, registrations_per_ip_per_day=1)
    await db.set_registration_enabled(per_ip_ds.get_internal_database(), "root", True)
    assert (await submit(per_ip_ds, "user1", ip="5.5.5.5")).status_code == 200
    per_ip = await submit(per_ip_ds, "user2", ip="5.5.5.5")

    queue_ds = await make_ds(trust_proxy_headers=True, max_pending_registrations=1)
    await db.set_registration_enabled(queue_ds.get_internal_database(), "root", True)
    assert (await submit(queue_ds, "user1", ip="5.5.5.5")).status_code == 200
    queue = await submit(queue_ds, "user2", ip="7.7.7.7")

    # Which cap tripped must not be distinguishable from the response.
    assert per_ip.status_code == queue.status_code == 429
    assert per_ip.json() == queue.json() == {"ok": False, "error": GENERIC_CLOSED}


@pytest.mark.asyncio
async def test_cap_refusals_write_no_admin_audit_rows():
    ds = await make_ds(trust_proxy_headers=True, registrations_per_ip_per_day=1)
    internal = ds.get_internal_database()
    await db.set_registration_enabled(internal, "root", True)

    assert (await submit(ds, "user1", ip="5.5.5.5")).status_code == 200
    assert (await submit(ds, "user2", ip="5.5.5.5")).status_code == 429

    count = (
        await internal.execute(
            f"SELECT COUNT(*) FROM {db.ADMIN_AUDIT} WHERE operation = 'register'"
        )
    ).single_value()
    assert count == 1  # only the successful registration


@pytest.mark.asyncio
async def test_default_caps_leave_normal_registration_unaffected():
    # No overrides: a handful of registrations from one IP stay under both
    # default caps (5/day per IP, 20 pending).
    ds = await make_ds(trust_proxy_headers=True)
    internal = ds.get_internal_database()
    await db.set_registration_enabled(internal, "root", True)
    for i in range(3):
        assert (await submit(ds, f"user{i}", ip="5.5.5.5")).status_code == 200
