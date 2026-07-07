"""Admin-controlled permissions: capability grants (F1), acl bridge (F2),
valid-actors (F3).

These run against the real datasette-paper + datasette-acl plugins (dev deps),
using paper's global ``datasette-paper-create`` action as the worked example and
acl's groups for the group principal.
"""

import json
import sqlite3

import pytest
from datasette.app import Datasette
from datasette.plugins import pm

from datasette_accounts import db, grantable
from datasette_accounts.passwords import hash_password
from datasette_accounts.security import COOKIE_NAME, SIGN_NAMESPACE
from datasette_accounts.sessions import mint_token, token_sha256

JSON = {"content-type": "application/json"}
PAPER_CREATE = "datasette-paper-create"


async def make_ds(config=None, **plugin_config):
    metadata = {}
    if plugin_config:
        metadata = {"plugins": {"datasette-accounts": plugin_config}}
    ds = Datasette(memory=True, metadata=metadata, config=config)
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


async def admin_cookie(ds, actor_id):
    internal = ds.get_internal_database()
    raw = mint_token()
    await db.create_session(internal, actor_id, token_sha256(raw), 14, "ua", "1.1.1.1")
    return {COOKIE_NAME: ds.sign(raw, SIGN_NAMESPACE)}


async def make_group(ds, name, members=()):
    internal = ds.get_internal_database()
    await internal.execute_write("INSERT INTO acl_groups (name) VALUES (?)", [name])
    gid = (
        await internal.execute("SELECT id FROM acl_groups WHERE name = ?", [name])
    ).single_value()
    for actor_id in members:
        await internal.execute_write(
            "INSERT INTO acl_actor_groups (actor_id, group_id) VALUES (?, ?)",
            [actor_id, gid],
        )
    return gid


# --------------------------------------------------------------------------
# The worked example is real: paper registers a global create action
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_paper_create_is_a_grantable_global_action():
    ds = await make_ds()
    assert PAPER_CREATE in ds.actions
    assert ds.actions[PAPER_CREATE].resource_class is None
    assert PAPER_CREATE in grantable.grantable_names(ds)
    # Our own admin action + acl's super-permission are NOT grantable row-by-row.
    assert "datasette-accounts-admin" not in grantable.grantable_names(ds)
    assert "datasette-acl" not in grantable.grantable_names(ds)


# --------------------------------------------------------------------------
# F1 — capability grants
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_actor_grant_allows_only_that_actor():
    ds = await make_ds()
    internal = ds.get_internal_database()
    alice = await insert_user(ds, "alice")
    bob = await insert_user(ds, "bob")

    assert not await ds.allowed(action=PAPER_CREATE, actor={"id": alice})
    added = await db.grant_capability(
        internal,
        "root",
        action=PAPER_CREATE,
        principal_type="actor",
        target_actor_id=alice,
    )
    assert added is True
    assert await ds.allowed(action=PAPER_CREATE, actor={"id": alice})
    assert not await ds.allowed(action=PAPER_CREATE, actor={"id": bob})


@pytest.mark.asyncio
async def test_authenticated_and_public_audiences():
    ds = await make_ds()
    internal = ds.get_internal_database()

    await db.grant_capability(
        internal, "root", action=PAPER_CREATE, principal_type="authenticated"
    )
    # Any signed-in actor gets it; an anonymous request does not.
    assert await ds.allowed(action=PAPER_CREATE, actor={"id": "anyone"})
    assert not await ds.allowed(action=PAPER_CREATE, actor=None)

    await db.grant_capability(
        internal, "root", action=PAPER_CREATE, principal_type="everyone"
    )
    assert await ds.allowed(action=PAPER_CREATE, actor=None)


@pytest.mark.asyncio
async def test_group_grant_follows_membership():
    ds = await make_ds()
    internal = ds.get_internal_database()
    alice = await insert_user(ds, "alice")
    bob = await insert_user(ds, "bob")
    gid = await make_group(ds, "editors", members=[alice])

    await db.grant_capability(
        internal, "root", action=PAPER_CREATE, principal_type="group", group_id=gid
    )
    assert await ds.allowed(action=PAPER_CREATE, actor={"id": alice})  # member
    assert not await ds.allowed(action=PAPER_CREATE, actor={"id": bob})  # non-member


@pytest.mark.asyncio
async def test_grant_is_idempotent():
    ds = await make_ds()
    internal = ds.get_internal_database()
    alice = await insert_user(ds, "alice")
    assert (
        await db.grant_capability(
            internal,
            "root",
            action=PAPER_CREATE,
            principal_type="actor",
            target_actor_id=alice,
        )
        is True
    )
    assert (
        await db.grant_capability(
            internal,
            "root",
            action=PAPER_CREATE,
            principal_type="actor",
            target_actor_id=alice,
        )
        is False
    )
    count = (
        await internal.execute(
            f"SELECT COUNT(*) FROM {db.CAPABILITY_GRANTS} WHERE actor_id = ?", [alice]
        )
    ).single_value()
    assert count == 1


@pytest.mark.asyncio
async def test_grant_rejects_unknown_principals():
    ds = await make_ds()
    internal = ds.get_internal_database()
    with pytest.raises(db.InvalidGrantError):
        await db.grant_capability(
            internal,
            "root",
            action=PAPER_CREATE,
            principal_type="actor",
            target_actor_id="ghost",
        )
    with pytest.raises(db.InvalidGrantError):
        await db.grant_capability(
            internal, "root", action=PAPER_CREATE, principal_type="group", group_id=9999
        )


@pytest.mark.asyncio
async def test_check_constraint_rejects_malformed_rows():
    ds = await make_ds()
    internal = ds.get_internal_database()

    def bad(conn):
        # principal_type 'actor' but no actor_id → CHECK violation
        conn.execute(
            f"INSERT INTO {db.CAPABILITY_GRANTS} "
            "(action, principal_type, actor_id, group_id, created_at) "
            "VALUES ('x', 'actor', NULL, NULL, 't')"
        )

    with pytest.raises(sqlite3.IntegrityError):
        await internal.execute_write_fn(bad)


@pytest.mark.asyncio
async def test_revoke_removes_grant():
    ds = await make_ds()
    internal = ds.get_internal_database()
    alice = await insert_user(ds, "alice")
    await db.grant_capability(
        internal,
        "root",
        action=PAPER_CREATE,
        principal_type="actor",
        target_actor_id=alice,
    )
    grants = await db.list_capability_grants(internal)
    assert len(grants) == 1
    assert await db.revoke_capability(internal, "root", grants[0]["id"]) is True
    assert not await ds.allowed(action=PAPER_CREATE, actor={"id": alice})
    assert await db.revoke_capability(internal, "root", 123456) is False  # gone


@pytest.mark.asyncio
async def test_grant_writes_audit_row():
    ds = await make_ds()
    internal = ds.get_internal_database()
    alice = await insert_user(ds, "alice")
    await db.grant_capability(
        internal,
        "admin-actor",
        action=PAPER_CREATE,
        principal_type="actor",
        target_actor_id=alice,
    )
    row = (
        await internal.execute(
            f"SELECT operation, actor_id, target_id, detail FROM {db.ADMIN_AUDIT} "
            "WHERE operation = 'grant-capability'"
        )
    ).first()
    assert row["actor_id"] == "admin-actor"
    assert row["target_id"] == alice
    assert json.loads(row["detail"])["action"] == PAPER_CREATE


@pytest.mark.asyncio
async def test_resolver_survives_without_acl_group_tables():
    # The group clause is only emitted when acl's tables exist; drop them and a
    # normal actor grant must still resolve without a SQL error.
    ds = await make_ds()
    internal = ds.get_internal_database()
    await internal.execute_write("DROP TABLE acl_actor_groups")
    await internal.execute_write("DROP TABLE acl_groups")
    assert await db.acl_available(internal) is False
    alice = await insert_user(ds, "alice")
    await db.grant_capability(
        internal,
        "root",
        action=PAPER_CREATE,
        principal_type="actor",
        target_actor_id=alice,
    )
    assert await ds.allowed(action=PAPER_CREATE, actor={"id": alice})


# --------------------------------------------------------------------------
# F2 — accounts admins are acl admins
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_admin_is_granted_acl_permission():
    ds = await make_ds()
    admin = await insert_user(ds, "admin", is_admin=True)
    user = await insert_user(ds, "user")
    assert await ds.allowed(action="datasette-acl", actor={"id": admin})
    assert not await ds.allowed(action="datasette-acl", actor={"id": user})


@pytest.mark.asyncio
async def test_acl_bridge_can_be_disabled():
    ds = await make_ds(grant_acl_admin=False)
    admin = await insert_user(ds, "admin", is_admin=True)
    assert not await ds.allowed(action="datasette-acl", actor={"id": admin})


@pytest.mark.asyncio
async def test_disabled_admin_loses_acl_permission():
    ds = await make_ds()
    admin = await insert_user(ds, "admin", is_admin=True, disabled=True)
    assert not await ds.allowed(action="datasette-acl", actor={"id": admin})


# --------------------------------------------------------------------------
# F3 — valid actors exposed to acl
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_valid_actors_hook_returns_enabled_accounts():
    ds = await make_ds()
    await insert_user(ds, "alice")
    await insert_user(ds, "ghost", disabled=True)
    results = []
    for hook_result in pm.hook.datasette_acl_valid_actors(datasette=ds):
        value = await hook_result() if callable(hook_result) else hook_result
        results.extend(value)
    usernames = {r["display"] for r in results if isinstance(r, dict)}
    assert "alice" in usernames
    assert "ghost" not in usernames  # disabled accounts are excluded


# --------------------------------------------------------------------------
# API endpoints + authorization + D11 gating + D8 config display
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_capabilities_list_requires_admin():
    ds = await make_ds()
    user = await insert_user(ds, "user")
    cookie = await admin_cookie(ds, user)
    # non-admin actor → 403
    r = await ds.client.post(
        "/-/admin/api/capabilities/list", content="{}", headers=JSON, cookies=cookie
    )
    assert r.status_code == 403
    # GET (wrong method) → 405
    r = await ds.client.get("/-/admin/api/capabilities/list")
    assert r.status_code == 405


@pytest.mark.asyncio
async def test_capabilities_api_grant_and_revoke():
    ds = await make_ds()
    admin = await insert_user(ds, "admin", is_admin=True)
    cookie = await admin_cookie(ds, admin)

    r = await ds.client.post(
        "/-/admin/api/capabilities/list", content="{}", headers=JSON, cookies=cookie
    )
    body = r.json()
    assert body["ok"] and body["has_acl"] is True
    paper = next(a for a in body["actions"] if a["name"] == PAPER_CREATE)
    # write action → no everyone/anonymous offered (D11)
    assert "authenticated" in paper["offerable_principals"]
    assert "everyone" not in paper["offerable_principals"]

    # grant to authenticated
    r = await ds.client.post(
        "/-/admin/api/capabilities/grant",
        content=json.dumps({"action": PAPER_CREATE, "principal_type": "authenticated"}),
        headers=JSON,
        cookies=cookie,
    )
    assert r.json() == {"ok": True}
    assert await ds.allowed(action=PAPER_CREATE, actor={"id": "someone"})

    # find + revoke it
    r = await ds.client.post(
        "/-/admin/api/capabilities/list", content="{}", headers=JSON, cookies=cookie
    )
    paper = next(a for a in r.json()["actions"] if a["name"] == PAPER_CREATE)
    grant_id = paper["grants"][0]["id"]
    r = await ds.client.post(
        "/-/admin/api/capabilities/revoke",
        content=json.dumps({"id": grant_id}),
        headers=JSON,
        cookies=cookie,
    )
    assert r.json() == {"ok": True}
    assert not await ds.allowed(action=PAPER_CREATE, actor={"id": "someone"})


@pytest.mark.asyncio
async def test_api_rejects_public_audience_for_write_action():
    ds = await make_ds()
    admin = await insert_user(ds, "admin", is_admin=True)
    cookie = await admin_cookie(ds, admin)
    r = await ds.client.post(
        "/-/admin/api/capabilities/grant",
        content=json.dumps({"action": PAPER_CREATE, "principal_type": "everyone"}),
        headers=JSON,
        cookies=cookie,
    )
    assert r.status_code == 400


@pytest.mark.asyncio
async def test_api_public_audience_allowed_when_configured():
    ds = await make_ds(public_audience_actions=[PAPER_CREATE])
    admin = await insert_user(ds, "admin", is_admin=True)
    cookie = await admin_cookie(ds, admin)
    r = await ds.client.post(
        "/-/admin/api/capabilities/grant",
        content=json.dumps({"action": PAPER_CREATE, "principal_type": "everyone"}),
        headers=JSON,
        cookies=cookie,
    )
    assert r.json() == {"ok": True}
    assert await ds.allowed(action=PAPER_CREATE, actor=None)


@pytest.mark.asyncio
async def test_api_rejects_non_grantable_action():
    ds = await make_ds()
    admin = await insert_user(ds, "admin", is_admin=True)
    cookie = await admin_cookie(ds, admin)
    r = await ds.client.post(
        "/-/admin/api/capabilities/grant",
        content=json.dumps(
            {"action": "view-instance", "principal_type": "authenticated"}
        ),
        headers=JSON,
        cookies=cookie,
    )
    assert r.status_code == 400


@pytest.mark.asyncio
async def test_config_grants_are_surfaced_readonly():
    # A datasette.yaml permission block for the action shows up read-only (D8).
    ds = await make_ds(config={"permissions": {PAPER_CREATE: {"id": "alice"}}})
    admin = await insert_user(ds, "admin", is_admin=True)
    cookie = await admin_cookie(ds, admin)
    r = await ds.client.post(
        "/-/admin/api/capabilities/list", content="{}", headers=JSON, cookies=cookie
    )
    paper = next(a for a in r.json()["actions"] if a["name"] == PAPER_CREATE)
    assert paper["config_grants"]
    assert paper["config_grants"][0]["source"] == "permissions"
    assert "alice" in paper["config_grants"][0]["allow_json"]


@pytest.mark.asyncio
async def test_grantable_actions_allowlist_config():
    # An explicit allowlist restricts the grantable set exactly.
    ds = await make_ds(grantable_actions=[PAPER_CREATE])
    assert grantable.grantable_names(ds) == {PAPER_CREATE}
