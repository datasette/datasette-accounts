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
    STATE_COOKIE,
    STATE_NAMESPACE,
    AuthProvider,
    ExternalIdentity,
    finish_login,
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

    async def handle(self, datasette, request, subpath):
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
    names = []

    def _register(providers):
        name = f"link-providers-{len(names)}"
        mod = types.ModuleType(name)

        @hookimpl
        def datasette_accounts_auth_providers(datasette):
            return list(providers)

        mod.datasette_accounts_auth_providers = datasette_accounts_auth_providers
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
    assert start_url.startswith("/-/login/provider/echo/start?state=")
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
    data = json.loads(
        page.text.split('id="pageData">', 1)[1].split("</script>", 1)[0]
    )
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
    assert start_url.startswith("/-/login/provider/echo/start?state=")
    step_state = _state_cookie_from(r)

    # 2. Re-complete the echo flow (subject matches the linked identity) →
    #    302 forwarding into echo2's start, carrying the step-up proof.
    r2 = await ds.client.get(
        start_url + "&subject=existing",
        cookies={COOKIE_NAME: sess, STATE_COOKIE: step_state},
    )
    assert r2.status_code == 302
    forward = r2.headers["location"]
    assert forward.startswith("/-/login/provider/echo2/start?state=")
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
        f"/-/login/provider/echo2/start?state={value}&subject=new",
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
    value, cookie = _sign_link_state(
        ds, provider="echo", actor_id=user_a, step_up=None
    )
    r = await ds.client.get(
        f"/-/login/provider/echo/start?state={value}&subject=fresh",
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
        content=json.dumps(
            {"target_id": uid, "provider": "echo", "subject": "only"}
        ),
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
        content=json.dumps(
            {"target_id": uid, "provider": "echo", "subject": "only"}
        ),
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
        "/-/admin/api/list", content="{}", headers=JSON,
        cookies={COOKIE_NAME: admin_sess},
    )
    users = {u["username"]: u for u in r.json()["users"]}
    assert [i["subject"] for i in users["alice"]["identities"]] == ["gh-1"]
    assert users["alice"]["identities"][0]["label"] == "Echo"
    assert users["admin"]["identities"] == []
