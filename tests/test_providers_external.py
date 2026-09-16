"""External-identity login path, provisioning policy, and the m009 migration:
the ExternalIdentity branch of finish_login, the identities table, per-provider
signups modes, shared abuse caps, and the delete/reject/disable
identity-cascade rules.

A test provider (mounted by the ``register_provider`` fixture — never an
installed package) builds an ExternalIdentity from query args and calls
finish_login, letting each test drive an arbitrary (subject, hint, intent).
"""

import json

import pytest
from providers_util import (
    JSON,
    FakeRequest,
    enable_provider,
    insert_user,
    make_ds,
    session_count,
    set_signups,
)
from sqlite_utils import Database

from datasette_accounts import db, security
from datasette_accounts.internal_migrations import internal_migrations
from datasette_accounts.passwords import UNUSABLE_PASSWORD
from datasette_accounts.providers import AuthProvider, ExternalIdentity, finish_login
from datasette_accounts.security import COOKIE_NAME


# --------------------------------------------------------------------------
# Test provider: build an ExternalIdentity from the query string, then finish.
# --------------------------------------------------------------------------


class ExtProvider(AuthProvider):
    key = "echo"
    label = "Echo"
    start_path = "/-/echo-auth/start"
    paths = ("ext",)

    async def ext(self, datasette, request):
        args = request.args
        identity = ExternalIdentity(
            provider="echo",
            subject=args.get("subject"),
            email=args.get("email"),
            username_hint=args.get("hint"),
            display_name=args.get("display"),
        )
        state = {"i": args.get("intent") or "login", "n": args.get("next")}
        return await finish_login(
            datasette,
            request,
            identity,
            provider_key="echo",
            response_mode=args.get("mode") or "json",
            state=state,
        )


async def _last_audit(ds):
    internal = ds.get_internal_database()
    rows = await internal.execute(
        f"SELECT reason, provider, success FROM {db.LOGIN_AUDIT} "
        "ORDER BY id DESC LIMIT 1"
    )
    return dict(rows.rows[0]) if rows.rows else None


async def _ext(ds, subject, **args):
    qs = "&".join(f"{k}={v}" for k, v in {"subject": subject, **args}.items())
    return await ds.client.get(f"/-/echo-auth/ext?{qs}")


async def _link(ds, uid, subject, **kw):
    internal = ds.get_internal_database()
    await db.link_identity(
        internal,
        "root",
        uid,
        ExternalIdentity(provider="echo", subject=subject, **kw),
    )


# ==========================================================================
# Migration m009
# ==========================================================================


def test_migration_creates_tables_and_columns():
    sdb = Database(memory=True)
    internal_migrations.apply(sdb)
    assert "datasette_accounts_identities" in sdb.table_names()
    id_cols = {c.name for c in sdb["datasette_accounts_identities"].columns}
    assert id_cols == {
        "provider",
        "subject",
        "user_id",
        "email",
        "display_name",
        "created_at",
        "last_login_at",
    }
    sess_cols = {c.name for c in sdb["datasette_accounts_sessions"].columns}
    assert "provider" in sess_cols
    audit_cols = {c.name for c in sdb["datasette_accounts_login_audit"].columns}
    assert "provider" in audit_cols
    # Decision D6: no email column anywhere outside the identities table.
    assert "email" not in {c.name for c in sdb["datasette_accounts_users"].columns}


def test_migration_rewrites_registration_enabled_row():
    sdb = Database(memory=True)
    internal_migrations.apply(sdb, stop_before="m009_auth_providers")
    sdb["datasette_accounts_settings"].insert(
        {
            "key": "registration_enabled",
            "value": "1",
            "updated_at": db.now_iso(),
            "updated_by": None,
        }
    )
    internal_migrations.apply(sdb)
    rows = list(sdb.query("SELECT key, value FROM datasette_accounts_settings"))
    assert rows == [{"key": "provider:password:signups", "value": "approval"}]


def test_migration_no_settings_row_leaves_no_signups_row():
    sdb = Database(memory=True)
    internal_migrations.apply(sdb)
    rows = list(sdb.query("SELECT COUNT(*) AS n FROM datasette_accounts_settings"))
    assert rows[0]["n"] == 0


# ==========================================================================
# Username derivation (pure function)
# ==========================================================================


def test_derive_username_passthrough():
    assert db.derive_username("alice", "echo", set()) == "alice"


def test_derive_username_slugifies():
    # Uppercase + illegal chars + spaces dropped; leading non-alnum stripped.
    assert db.derive_username("Al!ce Smith", "echo", set()) == "alcesmith"
    assert db.derive_username("--Bob.Jones_", "echo", set()) == "bob.jones_"


def test_derive_username_dots_survive():
    # A domain-style hint (bluesky handle) keeps its dots — a valid username.
    assert db.derive_username("alice.example.com", "echo", set()) == "alice.example.com"
    assert security.validate_username("alice.example.com") is None


def test_derive_username_collision_suffix():
    assert db.derive_username("alice", "echo", {"alice"}) == "alice-2"
    assert db.derive_username("alice", "echo", {"alice", "alice-2"}) == "alice-3"
    # A callable "taken" works too (provision uses one against the live DB).
    taken = {"alice", "alice-2", "alice-3"}
    assert db.derive_username("alice", "echo", taken.__contains__) == "alice-4"


@pytest.mark.parametrize("hint", ["", "ab", "root", "!!!", None])
def test_derive_username_fallback_is_valid(hint):
    name = db.derive_username(hint, "echo", set())
    assert name.startswith("echo-")
    assert security.validate_username(name) is None


def test_derive_username_result_always_valid():
    for hint in ["alice", "Al!ce Smith", "root", "", "x"]:
        name = db.derive_username(hint, "prov", set())
        assert security.validate_username(name) is None


# ==========================================================================
# Linked identity → mint, provenance, last_login_at
# ==========================================================================


@pytest.mark.asyncio
async def test_linked_identity_mints_with_provenance(register_provider):
    register_provider(ExtProvider())
    ds = await make_ds()
    await enable_provider(ds, "echo")
    uid = await insert_user(ds, "alice")
    await _link(ds, uid, "subj-1", email="a@example.com", display_name="Alice")

    r = await _ext(ds, "subj-1", mode="json")
    assert r.status_code == 200
    assert r.json() == {"ok": True, "redirect": "/", "must_change_password": False}
    assert r.cookies.get(COOKIE_NAME)
    assert await session_count(ds) == 1

    internal = ds.get_internal_database()
    srows = await internal.execute(f"SELECT provider FROM {db.SESSIONS}")
    assert srows.rows[0][0] == "echo"
    ident = await db.get_identity(internal, "echo", "subj-1")
    assert ident["last_login_at"] is not None
    assert await _last_audit(ds) == {
        "reason": "success",
        "provider": "echo",
        "success": 1,
    }


@pytest.mark.asyncio
async def test_linked_identity_redirect_mode(register_provider):
    register_provider(ExtProvider())
    ds = await make_ds()
    await enable_provider(ds, "echo")
    uid = await insert_user(ds, "alice")
    await _link(ds, uid, "subj-1")
    r = await _ext(ds, "subj-1", mode="redirect", next="/dashboard")
    assert r.status_code == 302
    assert r.headers["location"] == "/dashboard"
    assert r.cookies.get(COOKIE_NAME)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "kw,reason",
    [
        ({"disabled": True}, "provider_disabled"),
        ({"expires_at": "2000-01-01T00:00:00.000+00:00"}, "provider_expired"),
        ({"pending": True}, "provider_pending"),
    ],
)
async def test_linked_identity_gates_refuse(register_provider, kw, reason):
    register_provider(ExtProvider())
    ds = await make_ds()
    await enable_provider(ds, "echo")
    uid = await insert_user(ds, "blocked", **kw)
    await _link(ds, uid, "subj-1")
    r = await _ext(ds, "subj-1", mode="json")
    assert r.status_code == 403
    assert r.json()["ok"] is False
    assert await session_count(ds) == 0
    audit = await _last_audit(ds)
    assert audit["reason"] == reason and audit["provider"] == "echo"


# ==========================================================================
# Defense-in-depth: a disabled provider can never mint via finish_login
# ==========================================================================


@pytest.mark.asyncio
async def test_disabled_provider_refuses_in_finish_login(register_provider):
    register_provider(ExtProvider())
    ds = await make_ds()  # echo installed but NOT enabled
    uid = await insert_user(ds, "alice")
    await _link(ds, uid, "subj-1")
    resp = await finish_login(
        ds,
        FakeRequest(),
        ExternalIdentity(provider="echo", subject="subj-1"),
        provider_key="echo",
        response_mode="json",
    )
    assert resp.status == 403
    assert await session_count(ds) == 0
    assert (await _last_audit(ds))["reason"] == "provider_disabled"


@pytest.mark.asyncio
async def test_cross_provider_identity_is_a_bug(register_provider):
    register_provider(ExtProvider())
    ds = await make_ds()
    await enable_provider(ds, "echo")
    with pytest.raises(ValueError, match="returned identity for"):
        await finish_login(
            ds,
            FakeRequest(),
            ExternalIdentity(provider="other", subject="s"),
            provider_key="echo",
            response_mode="json",
        )


# ==========================================================================
# Unmatched identity → signups policy
# ==========================================================================


@pytest.mark.asyncio
async def test_signups_off_generic_refusal(register_provider):
    register_provider(ExtProvider())
    ds = await make_ds()
    await enable_provider(ds, "echo")  # signups absent → off
    r = await _ext(ds, "ghost", mode="json")
    assert r.status_code == 403
    assert r.json()["error"] == "No account is linked to that identity."
    assert await session_count(ds) == 0
    audit = await _last_audit(ds)
    assert audit["reason"] == "provider_no_account" and audit["provider"] == "echo"
    # No account was created.
    internal = ds.get_internal_database()
    n = (await internal.execute(f"SELECT COUNT(*) FROM {db.USERS}")).rows[0][0]
    assert n == 0


@pytest.mark.asyncio
async def test_signups_approval_provisions_pending_no_session(register_provider):
    register_provider(ExtProvider())
    ds = await make_ds()
    await enable_provider(ds, "echo")
    await set_signups(ds, "echo", "approval")
    r = await _ext(ds, "newsubj", hint="Grace", mode="json")
    assert r.status_code == 200
    assert r.json() == {"ok": True}  # awaiting-approval outcome, no redirect
    assert not r.cookies.get(COOKIE_NAME)
    assert await session_count(ds) == 0

    internal = ds.get_internal_database()
    # Pending user created with an unusable password, linked to the identity.
    assert await db.count_pending_users(internal) == 1
    ident = await db.get_identity(internal, "echo", "newsubj")
    user = await db.get_user_by_id(internal, ident["user_id"])
    assert user["pending_approval"] == 1
    assert user["password_hash"] == UNUSABLE_PASSWORD
    assert user["username"] == "grace"
    audit = await _last_audit(ds)
    assert audit["reason"] == "register" and audit["provider"] == "echo"


@pytest.mark.asyncio
async def test_approval_then_approve_then_login_mints(register_provider):
    register_provider(ExtProvider())
    ds = await make_ds()
    await enable_provider(ds, "echo")
    await set_signups(ds, "echo", "approval")
    await _ext(ds, "newsubj", hint="grace", mode="json")
    internal = ds.get_internal_database()
    ident = await db.get_identity(internal, "echo", "newsubj")
    # Approve, then the same external identity signs in and gets a session.
    await db.approve_user(internal, "root", ident["user_id"])
    r = await _ext(ds, "newsubj", mode="json")
    assert r.status_code == 200
    assert r.cookies.get(COOKIE_NAME)
    assert await session_count(ds) == 1
    assert (await _last_audit(ds))["reason"] == "success"


@pytest.mark.asyncio
async def test_pending_account_second_login_refused(register_provider):
    register_provider(ExtProvider())
    ds = await make_ds()
    await enable_provider(ds, "echo")
    await set_signups(ds, "echo", "approval")
    await _ext(ds, "newsubj", hint="grace", mode="json")
    # Still pending → a subsequent login is refused with provider_pending.
    r = await _ext(ds, "newsubj", mode="json")
    assert r.status_code == 403
    assert await session_count(ds) == 0
    assert (await _last_audit(ds))["reason"] == "provider_pending"


@pytest.mark.asyncio
async def test_signups_auto_activates_and_mints(register_provider):
    register_provider(ExtProvider())
    ds = await make_ds()
    await enable_provider(ds, "echo")
    await set_signups(ds, "echo", "auto")
    r = await _ext(ds, "autosubj", hint="hank", mode="json")
    assert r.status_code == 200
    assert r.cookies.get(COOKIE_NAME)
    assert await session_count(ds) == 1
    internal = ds.get_internal_database()
    ident = await db.get_identity(internal, "echo", "autosubj")
    user = await db.get_user_by_id(internal, ident["user_id"])
    assert user["pending_approval"] == 0
    assert user["username"] == "hank"
    assert (await _last_audit(ds))["reason"] == "success"


# ==========================================================================
# Link / step-up intents never provision or mint on this path
# ==========================================================================


@pytest.mark.asyncio
@pytest.mark.parametrize("intent", ["link", "step-up"])
async def test_link_intents_never_provision_or_mint(register_provider, intent):
    register_provider(ExtProvider())
    ds = await make_ds()
    await enable_provider(ds, "echo")
    await set_signups(ds, "echo", "auto")  # would otherwise auto-provision
    # An unmatched identity under a link/step-up intent must NOT provision or
    # mint: it is an invalid-state refusal, and nothing is created.
    resp = await finish_login(
        ds,
        FakeRequest(),
        ExternalIdentity(provider="echo", subject="linksubj", username_hint="l"),
        provider_key="echo",
        response_mode="json",
        state={"i": intent, "n": None},
    )
    assert resp.status == 403
    internal = ds.get_internal_database()
    assert await db.get_identity(internal, "echo", "linksubj") is None
    assert await session_count(ds) == 0
    assert (await _last_audit(ds))["reason"] == "provider_state_invalid"


@pytest.mark.asyncio
@pytest.mark.parametrize("subject", ["", "   ", None])
async def test_lost_subject_is_refused_never_a_shared_account(
    register_provider, subject
):
    # A provider that lost the IdP's id (missing `sub`, empty header) must not
    # map every such visitor onto one account: refused + audited, nothing
    # provisioned, no session.
    register_provider(ExtProvider())
    ds = await make_ds()
    await enable_provider(ds, "echo")
    await set_signups(ds, "echo", "auto")
    resp = await finish_login(
        ds,
        FakeRequest(),
        ExternalIdentity(provider="echo", subject=subject),
        provider_key="echo",
        response_mode="json",
    )
    assert resp.status == 403
    internal = ds.get_internal_database()
    rows = await internal.execute(f"SELECT COUNT(*) FROM {db.IDENTITIES}")
    assert rows.rows[0][0] == 0
    assert await session_count(ds) == 0
    assert (await _last_audit(ds))["reason"] == "provider_bad_subject"


@pytest.mark.asyncio
async def test_password_signups_auto_is_refused():
    # The password provider's signups always land in the approval queue, so
    # "auto" is refused outright rather than accepted and treated as approval.
    ds = await make_ds()
    internal = ds.get_internal_database()
    with pytest.raises(ValueError, match="auto-activate"):
        await db.set_provider_signups(internal, "root", "password", "auto")
    assert await db.get_provider_signups(internal, "password") == "off"
    with pytest.raises(ValueError, match="Invalid signups mode"):
        await db.set_provider_signups(internal, "root", "echo", "maybe")


# ==========================================================================
# Shared abuse caps (password + external count against one per-IP budget)
# ==========================================================================


@pytest.mark.asyncio
async def test_password_registration_fills_cap_blocks_external(register_provider):
    register_provider(ExtProvider())
    ds = await make_ds(registrations_per_ip_per_day=1)
    await enable_provider(ds, "echo")
    await set_signups(ds, "echo", "approval")
    await set_signups(ds, "password", "approval")
    # One password self-registration (reason 'register') uses up the per-IP cap.
    pr = await ds.client.post(
        "/-/register/api/submit",
        content=json.dumps({"username": "pwperson", "password": "password123"}),
        headers=JSON,
    )
    assert pr.status_code == 200
    # The external approval flow now refuses — shared per-IP counter.
    r = await _ext(ds, "extsubj", hint="ext", mode="json")
    assert r.status_code == 429
    audit = await _last_audit(ds)
    assert audit["reason"] == "register" and audit["provider"] == "echo"
    # No external account was provisioned.
    internal = ds.get_internal_database()
    assert await db.get_identity(internal, "echo", "extsubj") is None


@pytest.mark.asyncio
async def test_external_provisioning_fills_cap_blocks_password(register_provider):
    register_provider(ExtProvider())
    ds = await make_ds(registrations_per_ip_per_day=1)
    await enable_provider(ds, "echo")
    await set_signups(ds, "echo", "approval")
    await set_signups(ds, "password", "approval")
    # One external approval provision (reason 'register') uses up the per-IP cap.
    er = await _ext(ds, "extsubj", hint="ext", mode="json")
    assert er.status_code == 200
    assert (await _last_audit(ds))["reason"] == "register"
    # Password self-registration now refuses.
    pr = await ds.client.post(
        "/-/register/api/submit",
        content=json.dumps({"username": "pwperson", "password": "password123"}),
        headers=JSON,
    )
    assert pr.status_code == 429


# ==========================================================================
# Identity cascades: delete/reject drop links; disable keeps them
# ==========================================================================


@pytest.mark.asyncio
async def test_delete_user_removes_identities():
    ds = await make_ds()
    internal = ds.get_internal_database()
    uid = await insert_user(ds, "alice")
    await _link(ds, uid, "subj-1")
    await db.delete_user(internal, "root", uid)
    assert await db.get_identity(internal, "echo", "subj-1") is None


@pytest.mark.asyncio
async def test_reject_user_removes_identities():
    ds = await make_ds()
    internal = ds.get_internal_database()
    uid = await insert_user(ds, "grace", pending=True)
    await _link(ds, uid, "subj-1")
    await db.reject_user(internal, "root", uid)
    assert await db.get_identity(internal, "echo", "subj-1") is None


@pytest.mark.asyncio
async def test_disable_keeps_identities_and_reenable_restores_login(register_provider):
    register_provider(ExtProvider())
    ds = await make_ds()
    await enable_provider(ds, "echo")
    internal = ds.get_internal_database()
    uid = await insert_user(ds, "alice")
    await _link(ds, uid, "subj-1")

    await db.disable_user(internal, "root", uid)
    # Identity survives a disable (design §5) ...
    assert await db.get_identity(internal, "echo", "subj-1") is not None
    # ... but login is refused while disabled.
    r = await _ext(ds, "subj-1", mode="json")
    assert r.status_code == 403
    assert (await _last_audit(ds))["reason"] == "provider_disabled"

    # Re-enabling restores SSO access.
    await db.enable_user(internal, "root", uid)
    r = await _ext(ds, "subj-1", mode="json")
    assert r.status_code == 200
    assert r.cookies.get(COOKIE_NAME)


@pytest.mark.asyncio
async def test_list_identities_for_user():
    ds = await make_ds()
    internal = ds.get_internal_database()
    uid = await insert_user(ds, "alice")
    await _link(ds, uid, "subj-1", email="a@x.com")
    rows = await db.list_identities(internal, uid)
    assert [r["subject"] for r in rows] == ["subj-1"]
    assert rows[0]["provider"] == "echo"
