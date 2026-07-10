"""The built-in username/password provider (design §8).

The password flow is *literally* a provider: this module owns the credential
verify (login), the self-registration submit, and the mounted uniformity
surface. The canonical routes in ``routes/api.py`` (`/-/login/api/authenticate`,
`/-/register/api/submit`, `/-/set-password/api/complete`) keep their paths and
delegate here; every successful mint converges on ``finish_login`` /
``mint_session`` in ``providers/__init__``.

The KDF calls in ``verify_credentials`` go through the ``routes.api`` module on
purpose: the timing-discipline tests monkeypatch ``api.averify_dummy`` to assert
that exactly one PBKDF2 verify runs on every branch. Routing the calls through
that module keeps those assertions valid after the move.
"""

from urllib.parse import quote

from datasette import NotFound, Response

from .. import db, security
from ..passwords import (
    UNUSABLE_PASSWORD,
    PasswordLengthError,
    ahash_password,
    check_password_length,
)
from . import AuthProvider

# The user-facing login error is deliberately generic — the specific reason
# lives only in the admin-only login_audit.
GENERIC_LOGIN_ERROR = "Invalid username or password"


class PasswordProvider(AuthProvider):
    """Built-in username/password provider — always first in the registry.

    The canonical ``/-/login`` / ``/-/register`` / ``/-/set-password`` routes are
    the real, documented password surface; the mounted path exists only for
    uniformity (design §8) and bounces to ``/-/login`` (preserving a validated
    ``?next=``).
    """

    key = "password"
    label = "Username & password"

    async def handle(self, datasette, request, subpath: str):
        base_url = datasette.setting("base_url") or "/"
        next_value = security.validate_next(request.args.get("next"), base_url)
        target = datasette.urls.path("/-/login")
        if next_value and next_value != base_url:
            target += "?next=" + quote(next_value, safe="/")
        return Response.redirect(target)


async def verify_credentials(datasette, request, username, password):
    """Run the login verify half: lockout, one-KDF discipline, audit + lockout
    bookkeeping. Returns the authenticated user dict on success, or an error
    ``Response`` (429/401) to send verbatim. The caller mints via finish_login.

    Moved verbatim from authenticate(); the timing-discipline comments are the
    documentation and must stay intact.
    """
    # Imported here (not at module top) to avoid an import cycle — routes.api
    # imports this module. The tests monkeypatch api.averify_dummy /
    # api.averify_password, so the KDF must be reached through the api module.
    from ..routes import api

    internal = datasette.get_internal_database()
    ip = security.client_ip(datasette, request)
    threshold = security.config(datasette, "lockout_threshold")
    minutes = security.config(datasette, "lockout_minutes")

    user = await db.get_user_by_username(internal, username)

    # 1. Locked account: refuse before hashing (the only hash-skipping path).
    if user and user["locked_until"] and user["locked_until"] > db.now_iso():
        await db.record_login_attempt(internal, username, ip, False, "locked")
        return Response.json({"ok": False, "error": GENERIC_LOGIN_ERROR}, status=429)

    # 2/3. Exactly one PBKDF2 verify on every remaining path (dummy on miss).
    # The user-facing error stays generic; the specific reason lives only in the
    # admin-only audit log. An invited account (no usable password yet), an
    # expired account, and a self-registered account still awaiting approval
    # all take the same dummy-verify branch as no-such-user/disabled — none of
    # them may be distinguishable by response or timing. Telling the *visitor*
    # their account is pending is the register page's job, not the login form's
    # — the login form must not confirm account state to a third party.
    expired = bool(user and user["expires_at"] and user["expires_at"] <= db.now_iso())
    pending = bool(user and user["pending_approval"])
    has_password = user and user["password_hash"] != UNUSABLE_PASSWORD
    if user and not user["disabled"] and not expired and not pending and has_password:
        ok = await api.averify_password(password, user["password_hash"])
        reason = "success" if ok else "bad_password"
    else:
        await api.averify_dummy(password)
        ok = False
        # Precedence when more than one applies (e.g. a disabled account whose
        # expiry has also passed): disabled > expired > pending_approval >
        # no_password.
        if not user:
            reason = "no_such_user"
        elif user["disabled"]:
            reason = "disabled"
        elif expired:
            reason = "expired"
        elif pending:
            reason = "pending_approval"
        else:
            reason = "no_password"

    await db.record_login_attempt(internal, username, ip, ok, reason)

    if not ok:
        if user:
            await db.register_failed_attempt(internal, user["id"], threshold, minutes)
        return Response.json({"ok": False, "error": GENERIC_LOGIN_ERROR}, status=401)

    # Verify passed — hand the user back so the caller mints via finish_login.
    return user


async def register(datasette, request, body):
    """Self-registration submit (moved verbatim from register_submit).

    A disabled password provider means no password signups at all, regardless of
    the signups toggle — so refuse (404) when either is off.
    """
    internal = datasette.get_internal_database()
    # Re-checked here, not just on the GET page — the toggle can flip between
    # page load and submit. A disabled password provider also closes signups
    # (design §8). No audit row for this refusal: an unauthenticated probe
    # against a closed endpoint isn't a registration attempt.
    if not await db.get_provider_enabled(
        internal, "password"
    ) or not await db.get_registration_enabled(internal):
        raise NotFound("Not found")

    ip = security.client_ip(datasette, request)

    # Abuse caps (fail generic and closed), checked before validation/hashing
    # so a capped client can't spend our KDF time: a per-IP daily cap counted
    # from the 'register' rows already in login_audit, and a global
    # pending-queue cap. One message for both — which limit tripped is an
    # abuse signal we don't reveal. 429 (not 400): the request itself is
    # well-formed; the refusal is about volume/state, the same semantics as
    # the lockout path's 429.
    per_ip_cap = security.config(datasette, "registrations_per_ip_per_day")
    queue_cap = security.config(datasette, "max_pending_registrations")
    if (
        await db.count_recent_registrations(internal, ip) >= per_ip_cap
        or await db.count_pending_users(internal) >= queue_cap
    ):
        # Refused attempts are recorded too — repeat abuse counts toward the
        # per-IP cap rather than probing it for free.
        await db.record_login_attempt(internal, body.username, ip, False, "register")
        return Response.json(
            {
                "ok": False,
                "error": "Registration is currently closed — try again later.",
            },
            status=429,
        )

    error = security.validate_username(body.username)
    if error:
        return Response.json({"ok": False, "error": error}, status=400)
    try:
        check_password_length(
            body.password, security.config(datasette, "password_min_length")
        )
    except PasswordLengthError as e:
        return Response.json({"ok": False, "error": str(e)}, status=400)

    password_hash = await ahash_password(body.password)
    try:
        await db.register_user(internal, body.username, password_hash, ip)
    except db.UsernameTakenError:
        # Yes, this confirms the username is taken — a signup form cannot
        # avoid that. It's exactly why accounts stay pending and invisible
        # until a human approves them.
        await db.record_login_attempt(internal, body.username, ip, False, "register")
        return Response.json(
            {"ok": False, "error": "Username already taken"}, status=409
        )
    await db.record_login_attempt(internal, body.username, ip, True, "register")
    # No session: the account is pending, so nothing to sign in to yet.
    return Response.json({"ok": True})
