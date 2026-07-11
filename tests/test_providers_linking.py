"""Identity linking with step-up proof, strand-guarded unlink, admin unlink.

Ticket todos/auth-providers/04: the link-start endpoint (password step-up +
password-less step-up-via-provider), the link/step-up intent handling in
finish_login, the strand-guarded self + admin unlink, and the account/admin
page-data additions.

Kept in its own file so tests/test_providers*.py (tickets 01/02/03) stay
untouched. A read_state-driven test provider models a "pretend IdP": its start
handler reads the *signed* state (so intent/actor_id/step_up come from the
cookie, never the query string) and turns a query `subject` into an
ExternalIdentity — the exact seam a real OAuth callback would hit.
"""

import json
import types

import pytest
from datasette import Response, hookimpl
from datasette.app import Datasette
from datasette.plugins import pm

from datasette_accounts import db
from datasette_accounts.passwords import UNUSABLE_PASSWORD, hash_password
from datasette_accounts.providers import (
    GENERIC_FLOW_ERROR,
    STATE_COOKIE,
    STATE_NAMESPACE,
    AuthProvider,
    ExternalIdentity,
    finish_login,
    provider_gate,
    read_state,
)
from datasette_accounts.security import COOKIE_NAME, SIGN_NAMESPACE
from datasette_accounts.sessions import mint_token, token_sha256

JSON = {"content-type": "application/json"}


# --------------------------------------------------------------------------
# Test provider: a "pretend IdP" whose start reads the signed state and builds
# an ExternalIdentity from the query `subject`, then terminates via finish_login.
# --------------------------------------------------------------------------


class LinkProvider(AuthProvider):
    def __init__(self, key, label):
        self.key = key
        self.label = label
        self.start_path = f"/-/{key}-auth/start"

    async def serve(self, datasette, request):
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


@pytest.fixture
def register_providers():
    """Register the provider descriptors AND their own routes (design D3b): each
    provider owns ``/-/{key}-auth/...`` via a normal ``register_routes`` hook,
    every route wrapped in ``provider_gate`` for the enabled-404 + CSRF gate."""
    names = []

    def _register(providers):
        name = f"link-providers-{len(names)}"
        mod = types.ModuleType(name)

        @hookimpl
        def datasette_accounts_auth_providers(datasette):
            return list(providers)

        def _make_view(provider):
            @provider_gate(provider.key)
            async def _view(datasette, request):
                return await provider.serve(datasette, request)

            return _view

        @hookimpl
        def register_routes():
            return [
                (rf"/-/{p.key}-auth/(?P<rest>.*)$", _make_view(p)) for p in providers
            ]

        mod.datasette_accounts_auth_providers = datasette_accounts_auth_providers
        mod.register_routes = register_routes
        pm.register(mod, name=name)
        names.append(name)

    yield _register
    for name in names:
        if pm.get_plugin(name) is not None:
            pm.unregister(name=name)


async def make_ds(**plugin_config):
    metadata = {}
    if plugin_config:
        metadata = {"plugins": {"datasette-accounts": plugin_config}}
    ds = Datasette(memory=True, metadata=metadata)
    await ds.invoke_startup()
    return ds


async def _set_setting(ds, key, value):
    internal = ds.get_internal_database()
    await internal.execute_write(
        f"INSERT OR REPLACE INTO {db.SETTINGS} (key, value, updated_at) "
        "VALUES (?, ?, ?)",
        [key, value, db.now_iso()],
    )


async def _enable(ds, key):
    await _set_setting(ds, f"provider:{key}:enabled", "1")


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


async def make_admin(ds, username):
    uid = await insert_user(ds, username)
    internal = ds.get_internal_database()
    await internal.execute_write(
        f"UPDATE {db.USERS} SET is_admin = 1 WHERE id = ?", [uid]
    )
    return uid


async def _session_cookie(ds, uid):
    """Mint a real session for `uid` and return the signed cookie value — works
    for password-less accounts too (no password login needed)."""
    internal = ds.get_internal_database()
    raw = mint_token()
    await db.create_session(internal, uid, token_sha256(raw), 14, "ua", "1.1.1.1")
    return ds.sign(raw, SIGN_NAMESPACE)


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


def _state_cookie_from(resp):
    return resp.cookies.get(STATE_COOKIE)


# ==========================================================================
# Link-start endpoint — password step-up
# ==========================================================================


@pytest.mark.asyncio
async def test_link_happy_path_password_account(register_providers):
    register_providers([LinkProvider("echo", "Echo")])
    ds = await make_ds()
    await _enable(ds, "echo")
    uid = await insert_user(ds, "alice")
    sess = await _session_cookie(ds, uid)

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
    state_cookie = _state_cookie_from(r)
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
    # Audit + account page data both reflect the link.
    assert await _audit_ops(ds, "link-identity") == [
        {"provider": "echo", "subject": "gh-1"}
    ]
    page = await ds.client.get("/-/account", cookies={COOKIE_NAME: sess})
    data = json.loads(page.text.split('id="pageData">', 1)[1].split("</script>", 1)[0])
    assert [i["subject"] for i in data["identities"]] == ["gh-1"]
    assert data["identities"][0]["label"] == "Echo"
    assert data["has_password"] is True
    assert data["linkable_providers"] == []  # the one external provider is linked


@pytest.mark.asyncio
async def test_link_start_wrong_password_ticks_lockout(register_providers):
    register_providers([LinkProvider("echo", "Echo")])
    ds = await make_ds()
    await _enable(ds, "echo")
    uid = await insert_user(ds, "alice")
    sess = await _session_cookie(ds, uid)

    r = await ds.client.post(
        "/-/account/api/link-start",
        content=json.dumps({"provider": "echo", "password": "WRONG"}),
        headers=JSON,
        cookies={COOKIE_NAME: sess},
    )
    assert r.status_code == 401
    assert "start_url" not in r.json()
    assert not _state_cookie_from(r)
    # Lockout parity: the failed step-up counts toward the lockout counter.
    assert await _failed_attempts(ds, uid) == 1


@pytest.mark.asyncio
async def test_link_start_rejects_bad_target(register_providers):
    register_providers([LinkProvider("echo", "Echo")])
    ds = await make_ds()
    await _enable(ds, "echo")
    uid = await insert_user(ds, "alice")
    sess = await _session_cookie(ds, uid)

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
    sess = await _session_cookie(ds, uid)
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
    await _enable(ds, "echo")  # enabled, but configured() is False
    uid = await insert_user(ds, "alice")
    sess = await _session_cookie(ds, uid)
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
    await _enable(ds, "echo")
    await _enable(ds, "echo2")
    uid = await insert_user(ds, "sso", password_less=True)
    await _link(ds, uid, "echo", "existing")  # the already-linked method
    sess = await _session_cookie(ds, uid)

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
    step_state = _state_cookie_from(r)

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
    fwd_state = _state_cookie_from(r2)

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
    await _enable(ds, "echo")
    await _enable(ds, "echo2")
    uid = await insert_user(ds, "sso", password_less=True)
    await _link(ds, uid, "echo", "mine")
    other = await insert_user(ds, "other", password_less=True)
    await _link(ds, other, "echo", "theirs")
    sess = await _session_cookie(ds, uid)

    r = await ds.client.post(
        "/-/account/api/link-start",
        content=json.dumps({"provider": "echo2", "step_up_provider": "echo"}),
        headers=JSON,
        cookies={COOKIE_NAME: sess},
    )
    start_url = r.json()["start_url"]
    step_state = _state_cookie_from(r)
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
    await _enable(ds, "echo2")
    uid = await insert_user(ds, "sso", password_less=True)
    sess = await _session_cookie(ds, uid)

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
    await _enable(ds, "echo")
    victim = await insert_user(ds, "victim")
    await _link(ds, victim, "echo", "victim-subj")
    attacker = await insert_user(ds, "attacker")
    a_sess = await _session_cookie(ds, attacker)

    r = await ds.client.post(
        "/-/account/api/link-start",
        content=json.dumps({"provider": "echo", "password": "password123"}),
        headers=JSON,
        cookies={COOKIE_NAME: a_sess},
    )
    start_url = r.json()["start_url"]
    state_cookie = _state_cookie_from(r)

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
    await _enable(ds, "echo")
    user_a = await insert_user(ds, "aaa")
    user_b = await insert_user(ds, "bbb")
    b_sess = await _session_cookie(ds, user_b)

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
    await _enable(ds, "echo")
    uid = await insert_user(ds, "sso", password_less=True)
    await _link(ds, uid, "echo", "only")
    sess = await _session_cookie(ds, uid)
    admin_id = await make_admin(ds, "admin")
    admin_sess = await _session_cookie(ds, admin_id)

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
async def test_unlink_allowed_when_password_present(register_providers):
    register_providers([LinkProvider("echo", "Echo")])
    ds = await make_ds()
    await _enable(ds, "echo")
    uid = await insert_user(ds, "alice")  # has a password
    await _link(ds, uid, "echo", "only")
    sess = await _session_cookie(ds, uid)

    r = await ds.client.post(
        "/-/account/api/unlink",
        content=json.dumps({"provider": "echo", "subject": "only"}),
        headers=JSON,
        cookies={COOKIE_NAME: sess},
    )
    assert r.status_code == 200
    internal = ds.get_internal_database()
    assert await db.get_identity(internal, "echo", "only") is None
    assert await _audit_ops(ds, "unlink-identity") == [
        {"provider": "echo", "subject": "only"}
    ]


@pytest.mark.asyncio
async def test_unlink_someone_elses_identity_not_found(register_providers):
    register_providers([LinkProvider("echo", "Echo")])
    ds = await make_ds()
    await _enable(ds, "echo")
    owner = await insert_user(ds, "owner")
    await _link(ds, owner, "echo", "theirs")
    other = await insert_user(ds, "other")
    sess = await _session_cookie(ds, other)
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
    await _enable(ds, "echo")
    uid = await insert_user(ds, "alice")
    sess = await _session_cookie(ds, uid)

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
# Admin page data exposes each account's identities
# ==========================================================================


@pytest.mark.asyncio
async def test_admin_list_includes_identities(register_providers):
    register_providers([LinkProvider("echo", "Echo")])
    ds = await make_ds()
    await _enable(ds, "echo")
    uid = await insert_user(ds, "alice")
    await _link(ds, uid, "echo", "gh-1")
    admin_id = await make_admin(ds, "admin")
    admin_sess = await _session_cookie(ds, admin_id)

    r = await ds.client.post(
        "/-/admin/api/list",
        content="{}",
        headers=JSON,
        cookies={COOKIE_NAME: admin_sess},
    )
    users = {u["username"]: u for u in r.json()["users"]}
    assert [i["subject"] for i in users["alice"]["identities"]] == ["gh-1"]
    assert users["alice"]["identities"][0]["label"] == "Echo"
    assert users["admin"]["identities"] == []


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
    await _enable(ds, "echo")
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
    await _enable(ds, "echo")
    await _enable(ds, "echo2")
    uid = await insert_user(ds, "sso", password_less=True)
    await _link(ds, uid, "echo", "mine")  # a genuinely-owned, matchable identity
    sess = await _session_cookie(ds, uid)

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
    await _enable(ds, "echo")
    await _enable(ds, "echo2")
    uid = await insert_user(ds, "sso", password_less=True)
    await _link(ds, uid, "echo", "mine")
    sess = await _session_cookie(ds, uid)

    # A well-formed step-up start (echo2 target, echo step-up).
    r = await ds.client.post(
        "/-/account/api/link-start",
        content=json.dumps({"provider": "echo2", "step_up_provider": "echo"}),
        headers=JSON,
        cookies={COOKIE_NAME: sess},
    )
    start_url = r.json()["start_url"]
    step_state = _state_cookie_from(r)
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
    await _enable(ds, "echo")
    await _enable(ds, "echo2")
    uid = await insert_user(ds, "sso", password_less=True)
    await _link(ds, uid, "echo", "mine")
    sess = await _session_cookie(ds, uid)

    # link-start → a step-up state bound to provider `echo`.
    r = await ds.client.post(
        "/-/account/api/link-start",
        content=json.dumps({"provider": "echo2", "step_up_provider": "echo"}),
        headers=JSON,
        cookies={COOKIE_NAME: sess},
    )
    start_url = r.json()["start_url"]  # /-/echo-auth/start?state=VALUE
    step_state = _state_cookie_from(r)
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
    await _enable(ds, "echo")
    uid = await insert_user(ds, "alice")
    internal = ds.get_internal_database()
    await internal.execute_write(
        f"UPDATE {db.USERS} SET locked_until = ? WHERE id = ?",
        ["2999-01-01T00:00:00.000+00:00", uid],
    )
    sess = await _session_cookie(ds, uid)

    r = await ds.client.post(
        "/-/account/api/link-start",
        content=json.dumps({"provider": "echo", "password": "password123"}),
        headers=JSON,
        cookies={COOKIE_NAME: sess},
    )
    assert r.status_code == 429
    assert "start_url" not in r.json()
    assert not _state_cookie_from(r)
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
    await _enable(ds, "echo")
    uid = await insert_user(ds, "alice")
    sess = await _session_cookie(ds, uid)

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
    await _enable(ds, "echo")
    await _enable(ds, "echo2")
    await _enable(ds, "echo3")
    uid = await insert_user(ds, "sso", password_less=True)
    await _link(ds, uid, "echo", "mine")  # only echo is linked
    sess = await _session_cookie(ds, uid)

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
    assert not _state_cookie_from(r)
