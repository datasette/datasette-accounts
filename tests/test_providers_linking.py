"""Identity linking with step-up proof, strand-guarded unlink, admin unlink:
the link-start endpoint (password step-up + password-less step-up-via-provider),
the link/step-up intent handling in finish_login, and the strand-guarded self +
admin unlink. Self-unlink takes the same fresh proof as linking: password
accounts re-enter their password; password-less accounts re-complete ANOTHER
linked provider and the step-up leg performs the unlink.

A read_state-driven test provider models a "pretend IdP": its start handler
reads the *signed* state (so intent/actor_id/step_up come from the cookie,
never the query string) and turns a query `subject` into an ExternalIdentity —
the exact seam a real OAuth callback would hit. The flows are asserted at the
db + endpoint layer; the account/admin page data that surfaces them is covered
with the frontend.
"""

import json

import pytest
from datasette import Response
from providers_util import (
    JSON,
    enable_provider,
    insert_user,
    make_ds,
    session_cookie,
)

from datasette_accounts import db
from datasette_accounts.passwords import hash_password
from datasette_accounts.providers import (
    GENERIC_FLOW_ERROR,
    STATE_COOKIE,
    STATE_NAMESPACE,
    AuthProvider,
    ExternalIdentity,
    finish_login,
    read_state,
)
from datasette_accounts.security import COOKIE_NAME

# --------------------------------------------------------------------------
# Test provider: a "pretend IdP" whose start reads the signed state and builds
# an ExternalIdentity from the query `subject`, then terminates via finish_login.
# --------------------------------------------------------------------------


class LinkProvider(AuthProvider):
    paths = ("start",)

    def __init__(self, key, label):
        self.key = key
        self.label = label
        self.start_path = f"/-/{key}-auth/start"

    async def start(self, datasette, request):
        state = read_state(datasette, request, provider=self.key)
        if state is None:
            return Response.text("bad state", status=400)
        identity = ExternalIdentity(
            provider=self.key,
            subject=request.args.get("subject"),
            username_hint=request.args.get("hint"),
        )
        return await finish_login(
            datasette,
            request,
            identity,
            provider_key=self.key,
            response_mode="redirect",
            state=state,
        )


async def make_admin(ds, username):
    return await insert_user(ds, username, is_admin=True)


async def _link(ds, uid, provider, subject, **kw):
    internal = ds.get_internal_database()
    await db.link_identity(
        internal, uid, uid, ExternalIdentity(provider=provider, subject=subject, **kw)
    )


async def _failed_attempts(ds, uid):
    internal = ds.get_internal_database()
    rows = await internal.execute(
        f"SELECT failed_attempts FROM {db.USERS} WHERE id = ?", [uid]
    )
    return rows.rows[0][0]


async def _audit_ops(ds, operation):
    internal = ds.get_internal_database()
    rows = await internal.execute(
        f"SELECT detail FROM {db.ADMIN_AUDIT} WHERE operation = ? ORDER BY id",
        [operation],
    )
    return [json.loads(r[0]) if r[0] else None for r in rows.rows]


async def _login_reasons(ds):
    """Every login_audit reason, oldest first — lets a refusal test assert both
    that the expected reason was written and that nothing else was."""
    internal = ds.get_internal_database()
    rows = await internal.execute(f"SELECT reason FROM {db.LOGIN_AUDIT} ORDER BY id")
    return [r[0] for r in rows.rows]


# ==========================================================================
# Link-start endpoint — password step-up
# ==========================================================================


@pytest.mark.asyncio
async def test_link_happy_path_password_account(register_providers):
    register_providers([LinkProvider("echo", "Echo")])
    ds = await make_ds()
    await enable_provider(ds, "echo")
    uid = await insert_user(ds, "alice")
    sess = await session_cookie(ds, uid)

    # 1. Link-start with the correct password → a start_url + state cookie.
    r = await ds.client.post(
        "/-/account/api/link-start",
        content=json.dumps({"provider": "echo", "password": "password123"}),
        headers=JSON,
        cookies={COOKIE_NAME: sess},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["ok"] is True
    start_url = body["start_url"]
    assert start_url.startswith("/-/echo-auth/start?state=")
    state_cookie = r.cookies.get(STATE_COOKIE)
    assert state_cookie

    # 2. Drive the provider flow (intent=link rides in the signed state).
    r2 = await ds.client.get(
        start_url + "&subject=gh-1",
        cookies={COOKIE_NAME: sess, STATE_COOKIE: state_cookie},
    )
    assert r2.status_code == 302
    assert r2.headers["location"].endswith("/-/account")
    # No new session minted — linking never mints (we stay the same actor).
    assert not r2.cookies.get(COOKIE_NAME)

    internal = ds.get_internal_database()
    ident = await db.get_identity(internal, "echo", "gh-1")
    assert ident is not None and ident["user_id"] == uid
    # Audit reflects the link.
    assert await _audit_ops(ds, "link-identity") == [
        {"provider": "echo", "subject": "gh-1"}
    ]


@pytest.mark.asyncio
async def test_link_start_wrong_password_ticks_lockout(register_providers):
    register_providers([LinkProvider("echo", "Echo")])
    ds = await make_ds()
    await enable_provider(ds, "echo")
    uid = await insert_user(ds, "alice")
    sess = await session_cookie(ds, uid)

    r = await ds.client.post(
        "/-/account/api/link-start",
        content=json.dumps({"provider": "echo", "password": "WRONG"}),
        headers=JSON,
        cookies={COOKIE_NAME: sess},
    )
    assert r.status_code == 401
    assert "start_url" not in r.json()
    assert not r.cookies.get(STATE_COOKIE)
    # Lockout parity: the failed step-up counts toward the lockout counter.
    assert await _failed_attempts(ds, uid) == 1


@pytest.mark.asyncio
async def test_link_start_rejects_bad_target(register_providers):
    register_providers([LinkProvider("echo", "Echo")])
    ds = await make_ds()
    await enable_provider(ds, "echo")
    uid = await insert_user(ds, "alice")
    sess = await session_cookie(ds, uid)

    async def link_start(provider):
        return await ds.client.post(
            "/-/account/api/link-start",
            content=json.dumps({"provider": provider, "password": "password123"}),
            headers=JSON,
            cookies={COOKIE_NAME: sess},
        )

    # password (the built-in) is never a link target.
    assert (await link_start("password")).status_code == 400
    # An unknown provider key.
    assert (await link_start("nope")).status_code == 400
    # Already linked → not offered again.
    await _link(ds, uid, "echo", "gh-1")
    assert (await link_start("echo")).status_code == 400


@pytest.mark.asyncio
async def test_link_start_disabled_target_rejected(register_providers):
    register_providers([LinkProvider("echo", "Echo")])
    ds = await make_ds()  # echo installed but NOT enabled
    uid = await insert_user(ds, "alice")
    sess = await session_cookie(ds, uid)
    r = await ds.client.post(
        "/-/account/api/link-start",
        content=json.dumps({"provider": "echo", "password": "password123"}),
        headers=JSON,
        cookies={COOKIE_NAME: sess},
    )
    assert r.status_code == 400


class UnconfiguredLinkProvider(LinkProvider):
    """Enabled but not deployment-configured: configured() reports False."""

    def configured(self, datasette):
        return False


@pytest.mark.asyncio
async def test_link_start_unconfigured_target_rejected(register_providers):
    # Enabled but unconfigured (no credentials deployed): its start route would
    # 503, so it isn't a valid link target — same generic 400/message as a
    # disabled target (no distinguishable error on the non-admin surface).
    register_providers([UnconfiguredLinkProvider("echo", "Echo")])
    ds = await make_ds()
    await enable_provider(ds, "echo")  # enabled, but configured() is False
    uid = await insert_user(ds, "alice")
    sess = await session_cookie(ds, uid)
    r = await ds.client.post(
        "/-/account/api/link-start",
        content=json.dumps({"provider": "echo", "password": "password123"}),
        headers=JSON,
        cookies={COOKIE_NAME: sess},
    )
    assert r.status_code == 400
    assert r.json()["error"] == "That provider can't be linked."


# ==========================================================================
# Password-less step-up: re-complete a linked provider, forward into target
# ==========================================================================


@pytest.mark.asyncio
async def test_password_less_step_up_links_target(register_providers):
    register_providers([LinkProvider("echo", "Echo"), LinkProvider("echo2", "Echo2")])
    ds = await make_ds()
    await enable_provider(ds, "echo")
    await enable_provider(ds, "echo2")
    uid = await insert_user(ds, "sso", password_less=True)
    await _link(ds, uid, "echo", "existing")  # the already-linked method
    sess = await session_cookie(ds, uid)

    # 1. Link-start names echo2 as target + echo as the step-up method.
    r = await ds.client.post(
        "/-/account/api/link-start",
        content=json.dumps({"provider": "echo2", "step_up_provider": "echo"}),
        headers=JSON,
        cookies={COOKIE_NAME: sess},
    )
    assert r.status_code == 200
    start_url = r.json()["start_url"]
    assert start_url.startswith("/-/echo-auth/start?state=")
    step_state = r.cookies.get(STATE_COOKIE)

    # 2. Re-complete the echo flow (subject matches the linked identity) →
    #    302 forwarding into echo2's start, carrying the step-up proof.
    r2 = await ds.client.get(
        start_url + "&subject=existing",
        cookies={COOKIE_NAME: sess, STATE_COOKIE: step_state},
    )
    assert r2.status_code == 302
    forward = r2.headers["location"]
    assert forward.startswith("/-/echo2-auth/start?state=")
    assert not r2.cookies.get(COOKIE_NAME)  # no session minted at step-up
    fwd_state = r2.cookies.get(STATE_COOKIE)

    # 3. Complete echo2 (intent=link) → the new identity is linked.
    r3 = await ds.client.get(
        forward + "&subject=new-echo2",
        cookies={COOKIE_NAME: sess, STATE_COOKIE: fwd_state},
    )
    assert r3.status_code == 302
    assert r3.headers["location"].endswith("/-/account")
    internal = ds.get_internal_database()
    ident = await db.get_identity(internal, "echo2", "new-echo2")
    assert ident is not None and ident["user_id"] == uid


@pytest.mark.asyncio
async def test_step_up_subject_of_other_user_refused(register_providers):
    register_providers([LinkProvider("echo", "Echo"), LinkProvider("echo2", "Echo2")])
    ds = await make_ds()
    await enable_provider(ds, "echo")
    await enable_provider(ds, "echo2")
    uid = await insert_user(ds, "sso", password_less=True)
    await _link(ds, uid, "echo", "mine")
    other = await insert_user(ds, "other", password_less=True)
    await _link(ds, other, "echo", "theirs")
    sess = await session_cookie(ds, uid)

    r = await ds.client.post(
        "/-/account/api/link-start",
        content=json.dumps({"provider": "echo2", "step_up_provider": "echo"}),
        headers=JSON,
        cookies={COOKIE_NAME: sess},
    )
    start_url = r.json()["start_url"]
    step_state = r.cookies.get(STATE_COOKIE)
    # Present a subject that belongs to a DIFFERENT account → refused.
    r2 = await ds.client.get(
        start_url + "&subject=theirs",
        cookies={COOKIE_NAME: sess, STATE_COOKIE: step_state},
    )
    assert r2.status_code == 403
    internal = ds.get_internal_database()
    rows = await internal.execute(
        f"SELECT reason FROM {db.LOGIN_AUDIT} ORDER BY id DESC LIMIT 1"
    )
    assert rows.rows[0][0] == "provider_state_invalid"


@pytest.mark.asyncio
async def test_step_up_leg_requires_the_live_session(register_providers):
    # A step-up state lifted out of the acting user's browser proves nothing in
    # another one: even presenting the bound account's own identity, the leg
    # refuses when the LIVE session isn't the state's actor (or there is none).
    register_providers([LinkProvider("echo", "Echo"), LinkProvider("echo2", "Echo2")])
    ds = await make_ds()
    await enable_provider(ds, "echo")
    await enable_provider(ds, "echo2")
    uid = await insert_user(ds, "sso", password_less=True)
    await _link(ds, uid, "echo", "mine")
    attacker = await insert_user(ds, "attacker")
    sess = await session_cookie(ds, uid)
    r = await ds.client.post(
        "/-/account/api/link-start",
        content=json.dumps({"provider": "echo2", "step_up_provider": "echo"}),
        headers=JSON,
        cookies={COOKIE_NAME: sess},
    )
    start_url = r.json()["start_url"]
    step_state = r.cookies.get(STATE_COOKIE)
    for cookies in (
        {STATE_COOKIE: step_state},  # anonymous browser
        {COOKIE_NAME: await session_cookie(ds, attacker), STATE_COOKIE: step_state},
    ):
        r2 = await ds.client.get(start_url + "&subject=mine", cookies=cookies)
        assert r2.status_code == 403
        assert "location" not in r2.headers
        assert r2.cookies.get(STATE_COOKIE) in (None, "")
    assert (await _login_reasons(ds))[-2:] == ["provider_state_invalid"] * 2


@pytest.mark.asyncio
async def test_link_start_step_up_provider_must_be_usable(register_providers):
    # The already-linked provider named as step-up proof must itself still be
    # enabled + configured, or its start route would dead-end the visitor.
    register_providers([LinkProvider("echo", "Echo"), LinkProvider("echo2", "Echo2")])
    ds = await make_ds()
    await enable_provider(ds, "echo2")  # echo (the step-up) stays disabled
    uid = await insert_user(ds, "sso", password_less=True)
    await _link(ds, uid, "echo", "mine")
    r = await ds.client.post(
        "/-/account/api/link-start",
        content=json.dumps({"provider": "echo2", "step_up_provider": "echo"}),
        headers=JSON,
        cookies={COOKIE_NAME: await session_cookie(ds, uid)},
    )
    assert r.status_code == 400
    assert r.json()["error"] == "Choose a linked sign-in method to continue."
    assert r.cookies.get(STATE_COOKIE) is None


def _sign_link_state(ds, *, provider, actor_id, step_up, next="/-/account"):
    """Mint a fresh signed *link*-intent state cookie by hand, so a test can
    control the embedded step_up.at independent of the cookie's own freshness."""
    value = "test-state-value"
    payload = {
        "s": value,
        "p": provider,
        "n": next,
        "i": "link",
        "a": actor_id,
        "u": step_up,
        "c": db.now_iso(),  # cookie itself is fresh; step_up.at may be stale
    }
    return value, ds.sign(payload, STATE_NAMESPACE)


def _sign_step_up_state(ds, *, provider, actor_id, step_up, next="/-/account"):
    """Mint a signed *step-up*-intent state by hand — lets a test present a
    step-up state whose `u` payload is malformed (e.g. missing `target`) without
    routing through link-start, which always fills `target` in."""
    value = "test-step-up-value"
    payload = {
        "s": value,
        "p": provider,
        "n": next,
        "i": "step-up",
        "a": actor_id,
        "u": step_up,
        "c": db.now_iso(),
    }
    return value, ds.sign(payload, STATE_NAMESPACE)


@pytest.mark.asyncio
async def test_expired_step_up_proof_refused(register_providers):
    register_providers([LinkProvider("echo2", "Echo2")])
    ds = await make_ds()
    await enable_provider(ds, "echo2")
    uid = await insert_user(ds, "sso", password_less=True)
    sess = await session_cookie(ds, uid)

    # A link state whose cookie is fresh, but whose step_up proof is 20 min old
    # (default TTL is 10) → the link is refused on the proof window.
    stale = "2000-01-01T00:00:00.000+00:00"
    value, cookie = _sign_link_state(
        ds, provider="echo2", actor_id=uid, step_up={"provider": "echo", "at": stale}
    )
    r = await ds.client.get(
        f"/-/echo2-auth/start?state={value}&subject=new",
        cookies={COOKIE_NAME: sess, STATE_COOKIE: cookie},
    )
    assert r.status_code == 403
    internal = ds.get_internal_database()
    assert await db.get_identity(internal, "echo2", "new") is None


# ==========================================================================
# Link-intent security: already-linked + forged actor_id
# ==========================================================================


@pytest.mark.asyncio
async def test_link_to_identity_owned_by_victim_never_signs_in_as_victim(
    register_providers,
):
    """The nastiest case (security review): an attacker completes a LINK flow
    presenting an identity ALREADY linked to a victim. It must be refused with a
    generic page — never a session as the victim, never a re-link."""
    register_providers([LinkProvider("echo", "Echo")])
    ds = await make_ds()
    await enable_provider(ds, "echo")
    victim = await insert_user(ds, "victim")
    await _link(ds, victim, "echo", "victim-subj")
    attacker = await insert_user(ds, "attacker")
    a_sess = await session_cookie(ds, attacker)

    r = await ds.client.post(
        "/-/account/api/link-start",
        content=json.dumps({"provider": "echo", "password": "password123"}),
        headers=JSON,
        cookies={COOKIE_NAME: a_sess},
    )
    start_url = r.json()["start_url"]
    state_cookie = r.cookies.get(STATE_COOKIE)

    r2 = await ds.client.get(
        start_url + "&subject=victim-subj",
        cookies={COOKIE_NAME: a_sess, STATE_COOKIE: state_cookie},
    )
    # Generic refusal, NOT a redirect-to-account, and NO session cookie set.
    assert r2.status_code == 409
    assert "victim" not in r2.text  # no account disclosure
    assert not r2.cookies.get(COOKIE_NAME)
    internal = ds.get_internal_database()
    # The identity still belongs to the victim; the attacker gained nothing.
    ident = await db.get_identity(internal, "echo", "victim-subj")
    assert ident["user_id"] == victim
    assert await db.list_identities(internal, attacker) == []


@pytest.mark.asyncio
async def test_forged_actor_id_link_refused(register_providers):
    """A state built for user A, redeemed under user B's session → refused."""
    register_providers([LinkProvider("echo", "Echo")])
    ds = await make_ds()
    await enable_provider(ds, "echo")
    user_a = await insert_user(ds, "aaa")
    user_b = await insert_user(ds, "bbb")
    b_sess = await session_cookie(ds, user_b)

    # A link state bound to A (no step-up proof — a direct password-link state),
    # presented with B's live session.
    value, cookie = _sign_link_state(ds, provider="echo", actor_id=user_a, step_up=None)
    r = await ds.client.get(
        f"/-/echo-auth/start?state={value}&subject=fresh",
        cookies={COOKIE_NAME: b_sess, STATE_COOKIE: cookie},
    )
    assert r.status_code == 403
    internal = ds.get_internal_database()
    assert await db.get_identity(internal, "echo", "fresh") is None


# ==========================================================================
# Unlink: strand guard (self + admin), audits
# ==========================================================================


@pytest.mark.asyncio
async def test_unlink_strand_guard_self_and_admin(register_providers):
    register_providers([LinkProvider("echo", "Echo")])
    ds = await make_ds()
    await enable_provider(ds, "echo")
    uid = await insert_user(ds, "sso", password_less=True)
    await _link(ds, uid, "echo", "only")
    sess = await session_cookie(ds, uid)
    admin_id = await make_admin(ds, "admin")
    admin_sess = await session_cookie(ds, admin_id)

    # Self-unlink refused — it's the only sign-in method for a password-less user.
    r = await ds.client.post(
        "/-/account/api/unlink",
        content=json.dumps({"provider": "echo", "subject": "only"}),
        headers=JSON,
        cookies={COOKIE_NAME: sess},
    )
    assert r.status_code == 400
    assert "password" in r.json()["error"].lower()

    # Admin-unlink refused for the same reason (different message).
    r = await ds.client.post(
        "/-/admin/api/unlink-identity",
        content=json.dumps({"target_id": uid, "provider": "echo", "subject": "only"}),
        headers=JSON,
        cookies={COOKIE_NAME: admin_sess},
    )
    assert r.status_code == 400
    assert "Reset their password" in r.json()["error"]

    internal = ds.get_internal_database()
    assert await db.get_identity(internal, "echo", "only") is not None

    # Give the account a password → the strand guard clears; admin unlink works.
    await db.reset_password(internal, admin_id, uid, hash_password("newpass123"))
    r = await ds.client.post(
        "/-/admin/api/unlink-identity",
        content=json.dumps({"target_id": uid, "provider": "echo", "subject": "only"}),
        headers=JSON,
        cookies={COOKIE_NAME: admin_sess},
    )
    assert r.status_code == 200
    assert await db.get_identity(internal, "echo", "only") is None
    assert await _audit_ops(ds, "admin-unlink-identity") == [
        {"provider": "echo", "subject": "only"}
    ]


@pytest.mark.asyncio
async def test_unlink_password_account_requires_its_password(register_providers):
    register_providers([LinkProvider("echo", "Echo")])
    ds = await make_ds()
    await enable_provider(ds, "echo")
    uid = await insert_user(ds, "alice")  # has a password
    await _link(ds, uid, "echo", "only")
    sess = await session_cookie(ds, uid)
    internal = ds.get_internal_database()

    async def unlink(**extra):
        return await ds.client.post(
            "/-/account/api/unlink",
            content=json.dumps({"provider": "echo", "subject": "only", **extra}),
            headers=JSON,
            cookies={COOKIE_NAME: sess},
        )

    # No proof / wrong proof: refused, the identity stays, and — exactly like
    # link-start — a bad password ticks the lockout counter and is audited.
    r = await unlink()
    assert r.status_code == 401
    r = await unlink(password="wrong-password")
    assert r.status_code == 401
    assert r.json()["error"] == "Incorrect password"
    assert await _failed_attempts(ds, uid) == 2
    assert await db.get_identity(internal, "echo", "only") is not None
    assert await _audit_ops(ds, "unlink-identity") == []
    assert await _login_reasons(ds) == ["bad_password", "bad_password"]

    r = await unlink(password="password123")
    assert r.status_code == 200
    assert await db.get_identity(internal, "echo", "only") is None
    assert await _audit_ops(ds, "unlink-identity") == [
        {"provider": "echo", "subject": "only"}
    ]
    assert (await _login_reasons(ds))[-1:] == ["reauth"]


@pytest.mark.asyncio
async def test_unlink_password_less_via_step_up(register_providers):
    """A password-less account unlinks echo2 by re-completing echo: the route
    hands back a start_url into echo (intent=step-up, `u={"unlink": …}`), and
    the step-up leg performs the unlink instead of forwarding to a target."""
    register_providers([LinkProvider("echo", "Echo"), LinkProvider("echo2", "Echo2")])
    ds = await make_ds()
    await enable_provider(ds, "echo")
    await enable_provider(ds, "echo2")
    uid = await insert_user(ds, "sso", password_less=True)
    await _link(ds, uid, "echo", "keep")
    await _link(ds, uid, "echo2", "drop")
    sess = await session_cookie(ds, uid)
    internal = ds.get_internal_database()

    # The method being removed can't vouch for its own removal.
    r = await ds.client.post(
        "/-/account/api/unlink",
        content=json.dumps(
            {"provider": "echo2", "subject": "drop", "step_up_provider": "echo2"}
        ),
        headers=JSON,
        cookies={COOKIE_NAME: sess},
    )
    assert r.status_code == 400
    assert "linked sign-in method" in r.json()["error"]

    r = await ds.client.post(
        "/-/account/api/unlink",
        content=json.dumps(
            {"provider": "echo2", "subject": "drop", "step_up_provider": "echo"}
        ),
        headers=JSON,
        cookies={COOKIE_NAME: sess},
    )
    assert r.status_code == 200
    start_url = r.json()["start_url"]
    assert start_url.startswith("/-/echo-auth/start?state=")
    step_state = r.cookies.get(STATE_COOKIE)
    # Nothing is unlinked until the proof is shown.
    assert await db.get_identity(internal, "echo2", "drop") is not None

    # Re-complete echo with the matching subject → unlinked, back to /-/account,
    # no session minted, audited as the user's own unlink.
    r2 = await ds.client.get(
        start_url + "&subject=keep",
        cookies={COOKIE_NAME: sess, STATE_COOKIE: step_state},
    )
    assert r2.status_code == 302
    assert r2.headers["location"].endswith("/-/account")
    assert not r2.cookies.get(COOKIE_NAME)
    assert await db.get_identity(internal, "echo2", "drop") is None
    assert await db.get_identity(internal, "echo", "keep") is not None
    assert await _audit_ops(ds, "unlink-identity") == [
        {"provider": "echo2", "subject": "drop"}
    ]

    # The state was one-shot: replaying the proof finds nothing to unlink.
    r3 = await ds.client.get(
        start_url + "&subject=keep",
        cookies={COOKIE_NAME: sess, STATE_COOKIE: step_state},
    )
    assert r3.status_code == 404
    assert "not found" in r3.text.lower()


@pytest.mark.asyncio
async def test_step_up_unlink_state_tampering_refused(register_providers):
    """`_finish_step_up` honours exactly one unlock per state, and never lets
    the proving provider vouch for its own removal: a state naming both a
    target and an unlink, or an unlink of the step-up provider itself, is
    refused generically (`provider_state_invalid`); nothing changes."""
    register_providers([LinkProvider("echo", "Echo"), LinkProvider("echo2", "Echo2")])
    ds = await make_ds()
    await enable_provider(ds, "echo")
    await enable_provider(ds, "echo2")
    uid = await insert_user(ds, "sso", password_less=True)
    await _link(ds, uid, "echo", "keep")
    await _link(ds, uid, "echo2", "drop")
    sess = await session_cookie(ds, uid)
    internal = ds.get_internal_database()

    for step_up in (
        {"target": "echo2", "unlink": {"provider": "echo2", "subject": "drop"}},
        {"unlink": {"provider": "echo", "subject": "keep"}},
    ):
        value, cookie = _sign_step_up_state(
            ds, provider="echo", actor_id=uid, step_up=step_up
        )
        r = await ds.client.get(
            f"/-/echo-auth/start?state={value}&subject=keep",
            cookies={COOKIE_NAME: sess, STATE_COOKIE: cookie},
        )
        assert r.status_code == 403, step_up
        assert GENERIC_FLOW_ERROR in r.text
        assert not r.cookies.get(COOKIE_NAME)
    assert await db.get_identity(internal, "echo", "keep") is not None
    assert await db.get_identity(internal, "echo2", "drop") is not None
    assert await _login_reasons(ds) == ["provider_state_invalid"] * 2
    assert await _audit_ops(ds, "unlink-identity") == []


@pytest.mark.asyncio
async def test_unlink_someone_elses_identity_not_found(register_providers):
    register_providers([LinkProvider("echo", "Echo")])
    ds = await make_ds()
    await enable_provider(ds, "echo")
    owner = await insert_user(ds, "owner")
    await _link(ds, owner, "echo", "theirs")
    other = await insert_user(ds, "other")
    sess = await session_cookie(ds, other)
    # `other` tries to unlink an identity that isn't theirs → generic 404.
    r = await ds.client.post(
        "/-/account/api/unlink",
        content=json.dumps({"provider": "echo", "subject": "theirs"}),
        headers=JSON,
        cookies={COOKIE_NAME: sess},
    )
    assert r.status_code == 404
    internal = ds.get_internal_database()
    assert await db.get_identity(internal, "echo", "theirs") is not None


# ==========================================================================
# CSRF gate — link-start / unlink without JSON content-type are rejected
# ==========================================================================


@pytest.mark.asyncio
async def test_link_and_unlink_require_json_content_type(register_providers):
    register_providers([LinkProvider("echo", "Echo")])
    ds = await make_ds()
    await enable_provider(ds, "echo")
    uid = await insert_user(ds, "alice")
    sess = await session_cookie(ds, uid)

    for path, payload in (
        ("/-/account/api/link-start", {"provider": "echo", "password": "password123"}),
        ("/-/account/api/unlink", {"provider": "echo", "subject": "only"}),
    ):
        r = await ds.client.post(
            path,
            content=json.dumps(payload),
            headers={"content-type": "application/x-www-form-urlencoded"},
            cookies={COOKIE_NAME: sess},
        )
        assert r.status_code == 403


# ==========================================================================
# derive_username: the -N collision suffix must never break the length cap
# ==========================================================================


def test_derive_username_long_colliding_hint_stays_valid():
    from datasette_accounts import security

    # A 64-char slug that clears validate_username but collides: the naive
    # `base + "-2"` would be 66 chars (invalid). The trim keeps it ≤ 64.
    base = "a" * 64
    assert security.validate_username(base) is None
    taken = {base}
    name = db.derive_username(base, "echo", taken)
    assert name != base
    assert len(name) <= security.USERNAME_MAX_LENGTH
    assert security.validate_username(name) is None

    # Even a wall of collisions keeps producing valid names.
    taken = {base} | {f"{('a' * 64)[: 64 - len(f'-{i}')]}-{i}" for i in range(2, 50)}
    name = db.derive_username(base, "echo", taken)
    assert security.validate_username(name) is None


# ==========================================================================
# Backfills from the 19b4fa9 security review of the linking state machine
# ==========================================================================


@pytest.mark.asyncio
async def test_link_completion_while_signed_out_refused(register_providers):
    """`_finish_link` resolves the actor from the LIVE session cookie. A valid
    link state for user A, redeemed with NO session cookie at all (`live is None`)
    → generic refusal, no session minted, no identity linked. The existing
    forged-actor test only covers a *different* signed-in user."""
    register_providers([LinkProvider("echo", "Echo")])
    ds = await make_ds()
    await enable_provider(ds, "echo")
    uid = await insert_user(ds, "alice")

    value, cookie = _sign_link_state(ds, provider="echo", actor_id=uid, step_up=None)
    # No COOKIE_NAME (session) cookie — the visitor is fully signed out.
    r = await ds.client.get(
        f"/-/echo-auth/start?state={value}&subject=fresh",
        cookies={STATE_COOKIE: cookie},
    )
    assert r.status_code == 403
    assert GENERIC_FLOW_ERROR in r.text
    assert not r.cookies.get(COOKIE_NAME)
    internal = ds.get_internal_database()
    assert await db.get_identity(internal, "echo", "fresh") is None
    assert await _login_reasons(ds) == ["provider_state_invalid"]


@pytest.mark.asyncio
async def test_step_up_state_missing_target_refused(register_providers):
    """`_finish_step_up`'s `not target` clause: a step-up state whose `u` payload
    carries no `target` (never produced by link-start, but a tampered/rolled state
    could) → refused, generic, `provider_state_invalid`, no forward, no session."""
    register_providers([LinkProvider("echo", "Echo"), LinkProvider("echo2", "Echo2")])
    ds = await make_ds()
    await enable_provider(ds, "echo")
    await enable_provider(ds, "echo2")
    uid = await insert_user(ds, "sso", password_less=True)
    await _link(ds, uid, "echo", "mine")  # a genuinely-owned, matchable identity
    sess = await session_cookie(ds, uid)

    # Step-up state for echo, actor = uid, but `u` has no `target`.
    value, cookie = _sign_step_up_state(ds, provider="echo", actor_id=uid, step_up={})
    r = await ds.client.get(
        f"/-/echo-auth/start?state={value}&subject=mine",
        cookies={COOKIE_NAME: sess, STATE_COOKIE: cookie},
    )
    assert r.status_code == 403
    assert GENERIC_FLOW_ERROR in r.text
    assert not r.cookies.get(COOKIE_NAME)
    assert await _login_reasons(ds) == ["provider_state_invalid"]


@pytest.mark.asyncio
async def test_step_up_subject_matching_no_identity_refused(register_providers):
    """`_finish_step_up`'s `existing is None` branch: a valid step-up state, but
    the presented subject matches NO linked identity at all → refused, generic,
    `provider_state_invalid` (distinct from the subject-of-another-user case)."""
    register_providers([LinkProvider("echo", "Echo"), LinkProvider("echo2", "Echo2")])
    ds = await make_ds()
    await enable_provider(ds, "echo")
    await enable_provider(ds, "echo2")
    uid = await insert_user(ds, "sso", password_less=True)
    await _link(ds, uid, "echo", "mine")
    sess = await session_cookie(ds, uid)

    # A well-formed step-up start (echo2 target, echo step-up).
    r = await ds.client.post(
        "/-/account/api/link-start",
        content=json.dumps({"provider": "echo2", "step_up_provider": "echo"}),
        headers=JSON,
        cookies={COOKIE_NAME: sess},
    )
    start_url = r.json()["start_url"]
    step_state = r.cookies.get(STATE_COOKIE)
    # Present a subject nobody owns → get_identity returns None → refused.
    r2 = await ds.client.get(
        start_url + "&subject=ghost-subject",
        cookies={COOKIE_NAME: sess, STATE_COOKIE: step_state},
    )
    assert r2.status_code == 403
    assert GENERIC_FLOW_ERROR in r2.text
    assert not r2.cookies.get(COOKIE_NAME)
    internal = ds.get_internal_database()
    assert await db.get_identity(internal, "echo2", "ghost-subject") is None
    assert await _login_reasons(ds) == ["provider_state_invalid"]


@pytest.mark.asyncio
async def test_step_up_state_replayed_against_target_is_bad_state(register_providers):
    """Confusion-attack regression: the gen-1 step-up state is bound to the
    step-up provider (echo). Replaying it against the TARGET provider's start
    (echo2) trips `read_state`'s provider-mismatch guard → the provider returns
    'bad state' BEFORE finish_login, so nothing is linked and no login_audit row
    (state-invalid or otherwise) is written."""
    register_providers([LinkProvider("echo", "Echo"), LinkProvider("echo2", "Echo2")])
    ds = await make_ds()
    await enable_provider(ds, "echo")
    await enable_provider(ds, "echo2")
    uid = await insert_user(ds, "sso", password_less=True)
    await _link(ds, uid, "echo", "mine")
    sess = await session_cookie(ds, uid)

    # link-start → a step-up state bound to provider `echo`.
    r = await ds.client.post(
        "/-/account/api/link-start",
        content=json.dumps({"provider": "echo2", "step_up_provider": "echo"}),
        headers=JSON,
        cookies={COOKIE_NAME: sess},
    )
    start_url = r.json()["start_url"]  # /-/echo-auth/start?state=VALUE
    step_state = r.cookies.get(STATE_COOKIE)
    state_value = start_url.split("state=", 1)[1]

    # Replay that echo-bound state against echo2's start: read_state(provider=echo2)
    # sees payload p="echo" and returns None → LinkProvider's "bad state" 400.
    r2 = await ds.client.get(
        f"/-/echo2-auth/start?state={state_value}&subject=mine",
        cookies={COOKIE_NAME: sess, STATE_COOKIE: step_state},
    )
    assert r2.status_code == 400
    assert not r2.cookies.get(COOKIE_NAME)
    internal = ds.get_internal_database()
    assert await db.get_identity(internal, "echo2", "mine") is None
    # Refused at the state gate — no login_audit row of any kind.
    assert await _login_reasons(ds) == []


# ==========================================================================
# link-start error branches (early 4xx, before any KDF verify)
# ==========================================================================


@pytest.mark.asyncio
async def test_link_start_locked_account_429_no_kdf(register_providers, monkeypatch):
    """A locked account short-circuits to 429 BEFORE the password verify: the KDF
    must never run (mirrors the change-password re-auth lockout discipline). No
    verify, no failed-attempt tick, no state cookie."""
    import datasette_accounts.routes.api as api

    def boom(*a, **k):  # pragma: no cover - must never be called
        raise AssertionError("averify_password ran on a locked account")

    monkeypatch.setattr(api, "averify_password", boom)

    register_providers([LinkProvider("echo", "Echo")])
    ds = await make_ds()
    await enable_provider(ds, "echo")
    uid = await insert_user(ds, "alice")
    internal = ds.get_internal_database()
    await internal.execute_write(
        f"UPDATE {db.USERS} SET locked_until = ? WHERE id = ?",
        ["2999-01-01T00:00:00.000+00:00", uid],
    )
    sess = await session_cookie(ds, uid)

    r = await ds.client.post(
        "/-/account/api/link-start",
        content=json.dumps({"provider": "echo", "password": "password123"}),
        headers=JSON,
        cookies={COOKIE_NAME: sess},
    )
    assert r.status_code == 429
    assert "start_url" not in r.json()
    assert not r.cookies.get(STATE_COOKIE)
    # The locked branch returns before register_failed_attempt.
    assert await _failed_attempts(ds, uid) == 0


@pytest.mark.asyncio
async def test_link_start_target_validation_400s(register_providers, monkeypatch):
    """The target-validation 400s all fire before the KDF verify: `password` as a
    target, a nonexistent target, and an already-linked target. The verify must
    never run for any of them."""
    import datasette_accounts.routes.api as api

    def boom(*a, **k):  # pragma: no cover - must never be called
        raise AssertionError("averify_password ran on an invalid target")

    monkeypatch.setattr(api, "averify_password", boom)

    register_providers([LinkProvider("echo", "Echo")])
    ds = await make_ds()
    await enable_provider(ds, "echo")
    uid = await insert_user(ds, "alice")
    sess = await session_cookie(ds, uid)

    async def link_start(provider):
        return await ds.client.post(
            "/-/account/api/link-start",
            content=json.dumps({"provider": provider, "password": "password123"}),
            headers=JSON,
            cookies={COOKIE_NAME: sess},
        )

    assert (await link_start("password")).status_code == 400  # built-in, never a target
    assert (await link_start("nope")).status_code == 400  # nonexistent provider
    await _link(ds, uid, "echo", "gh-1")
    assert (await link_start("echo")).status_code == 400  # already linked


@pytest.mark.asyncio
async def test_link_start_password_less_unlinked_step_up_400(register_providers):
    """A password-less account naming a `step_up_provider` that isn't currently
    linked to it → 400, no state cookie, nothing linked."""
    register_providers(
        [
            LinkProvider("echo", "Echo"),
            LinkProvider("echo2", "Echo2"),
            LinkProvider("echo3", "Echo3"),
        ]
    )
    ds = await make_ds()
    await enable_provider(ds, "echo")
    await enable_provider(ds, "echo2")
    await enable_provider(ds, "echo3")
    uid = await insert_user(ds, "sso", password_less=True)
    await _link(ds, uid, "echo", "mine")  # only echo is linked
    sess = await session_cookie(ds, uid)

    # Target echo2 (valid, unlinked); step-up echo3 is installed but NOT linked
    # to this account → refused before any provider flow starts.
    r = await ds.client.post(
        "/-/account/api/link-start",
        content=json.dumps({"provider": "echo2", "step_up_provider": "echo3"}),
        headers=JSON,
        cookies={COOKIE_NAME: sess},
    )
    assert r.status_code == 400
    assert "start_url" not in r.json()
    assert not r.cookies.get(STATE_COOKIE)
