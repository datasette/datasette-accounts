"""JSON API endpoints: authenticate, logout, change-password, admin operations."""

from typing import Annotated

from datasette import Response
from datasette_plugin_router import Body

from .. import db, grantable, messages, security
from ..page_data import (
    AuthenticateRequest,
    ChangePasswordRequest,
    CreateUserRequest,
    GrantCapabilityRequest,
    LoginAttemptRow,
    LoginAttemptsRequest,
    ResetPasswordRequest,
    RevokeCapabilityRequest,
    RevokeSessionRequest,
    SessionRow,
    SetSiteMessageRequest,
    TargetRequest,
    UserRow,
)
from ..passwords import (
    UNUSABLE_PASSWORD,
    PasswordLengthError,
    ahash_password,
    averify_dummy,
    averify_password,
    check_password_length,
    generate_password,
)
from ..router import require_actor, require_admin, require_csrf, router
from ..security import COOKIE_NAME, SIGN_NAMESPACE
from ..sessions import mint_token, token_sha256

GENERIC_LOGIN_ERROR = "Invalid username or password"


def _current_token_sha(datasette, request):
    cookie = request.cookies.get(COOKIE_NAME)
    if not cookie:
        return None
    try:
        raw = datasette.unsign(cookie, SIGN_NAMESPACE)
    except Exception:
        return None
    return token_sha256(raw)


def _set_session_cookie(datasette, request, response, raw_token):
    response.set_cookie(
        COOKIE_NAME,
        datasette.sign(raw_token, SIGN_NAMESPACE),
        max_age=security.config(datasette, "session_ttl_days") * 86400,
        path="/",
        httponly=True,
        samesite="lax",
        secure=security.should_secure_cookie(datasette, request),
    )


# --------------------------------------------------------------------------
# Login / logout
# --------------------------------------------------------------------------


@router.POST("/-/login/api/authenticate$")
@require_csrf
async def authenticate(
    datasette, request, body: Annotated[AuthenticateRequest, Body()]
):
    internal = datasette.get_internal_database()
    ip = security.client_ip(datasette, request)
    threshold = security.config(datasette, "lockout_threshold")
    minutes = security.config(datasette, "lockout_minutes")

    user = await db.get_user_by_username(internal, body.username)

    # 1. Locked account: refuse before hashing (the only hash-skipping path).
    if user and user["locked_until"] and user["locked_until"] > db.now_iso():
        await db.record_login_attempt(internal, body.username, ip, False, "locked")
        return Response.json({"ok": False, "error": GENERIC_LOGIN_ERROR}, status=429)

    # 2/3. Exactly one PBKDF2 verify on every remaining path (dummy on miss).
    # The user-facing error stays generic; the specific reason lives only in the
    # admin-only audit log. An invited account (no usable password yet) takes
    # the same dummy-verify branch as no-such-user/disabled — it must be
    # indistinguishable by response or timing.
    has_password = user and user["password_hash"] != UNUSABLE_PASSWORD
    if user and not user["disabled"] and has_password:
        ok = await averify_password(body.password, user["password_hash"])
        reason = "success" if ok else "bad_password"
    else:
        await averify_dummy(body.password)
        ok = False
        if not user:
            reason = "no_such_user"
        elif user["disabled"]:
            reason = "disabled"
        else:
            reason = "no_password"

    await db.record_login_attempt(internal, body.username, ip, ok, reason)

    if not ok:
        if user:
            await db.register_failed_attempt(internal, user["id"], threshold, minutes)
        return Response.json({"ok": False, "error": GENERIC_LOGIN_ERROR}, status=401)

    # Success.
    await db.record_login_success(internal, user["id"])
    raw_token = mint_token()
    await db.create_session(
        internal,
        user["id"],
        token_sha256(raw_token),
        security.config(datasette, "session_ttl_days"),
        request.headers.get("user-agent"),
        ip,
    )
    await db.delete_expired_sessions(internal)
    await db.purge_expired_password_tokens(internal)
    await db.purge_login_audit(
        internal, security.config(datasette, "audit_retention_days")
    )

    base_url = datasette.setting("base_url") or "/"
    redirect = security.validate_next(body.next, base_url)
    response = Response.json(
        {
            "ok": True,
            "redirect": redirect,
            "must_change_password": bool(user["must_change_password"]),
        }
    )
    _set_session_cookie(datasette, request, response, raw_token)
    return response


@router.POST("/-/logout/perform$")
@require_csrf
async def logout(datasette, request):
    internal = datasette.get_internal_database()
    token_sha = _current_token_sha(datasette, request)
    if token_sha:
        await db.delete_session(internal, token_sha)
    response = Response.json({"ok": True, "redirect": "/"})
    response.set_cookie(COOKIE_NAME, "", max_age=0, path="/", expires=0)
    return response


# --------------------------------------------------------------------------
# Self-service change password
# --------------------------------------------------------------------------


@router.POST("/-/account/api/change-password$")
@require_actor
async def change_password(
    datasette, request, body: Annotated[ChangePasswordRequest, Body()]
):
    internal = datasette.get_internal_database()
    actor_id = request.actor["id"]
    user = await db.get_user_by_id(internal, actor_id)
    if not user:
        return Response.json({"ok": False, "error": "Unknown account"}, status=401)

    threshold = security.config(datasette, "lockout_threshold")
    minutes = security.config(datasette, "lockout_minutes")
    ip = security.client_ip(datasette, request)

    # First-login forced change: the session already proves the temp password
    # was entered at login, so don't demand it a second time. A normal, voluntary
    # change still re-verifies the current password (defends a walked-up session).
    if not user["must_change_password"]:
        if user["locked_until"] and user["locked_until"] > db.now_iso():
            return Response.json({"ok": False, "error": "Account locked"}, status=429)

        ok = await averify_password(body.current_password or "", user["password_hash"])
        await db.record_login_attempt(
            internal, user["username"], ip, ok, "reauth" if ok else "bad_password"
        )
        if not ok:
            await db.register_failed_attempt(internal, user["id"], threshold, minutes)
            return Response.json(
                {"ok": False, "error": "Current password is incorrect"}, status=401
            )

    try:
        check_password_length(
            body.new_password, security.config(datasette, "password_min_length")
        )
    except PasswordLengthError as e:
        return Response.json({"ok": False, "error": str(e)}, status=400)

    # The new password must differ from the current one (covers the forced-change
    # path too, where we never re-checked the current password above).
    if await averify_password(body.new_password, user["password_hash"]):
        return Response.json(
            {
                "ok": False,
                "error": "New password must be different from the current one",
            },
            status=400,
        )

    new_hash = await ahash_password(body.new_password)
    await db.change_own_password(
        internal, user["id"], new_hash, _current_token_sha(datasette, request)
    )
    return Response.json({"ok": True})


# --------------------------------------------------------------------------
# Admin operations
# --------------------------------------------------------------------------


def _resolve_password(datasette, provided, generate):
    """Return ``(plaintext, generated, error_response)``.

    When ``generate`` is set (or no password is provided) the server mints a
    strong random password; otherwise the admin-supplied one is length-checked.
    ``generated`` tells the caller whether the plaintext should be echoed back
    to the admin once. On a length violation ``error_response`` is set.
    """
    min_length = security.config(datasette, "password_min_length")
    if generate or not provided:
        return generate_password(min_length), True, None
    try:
        check_password_length(provided, min_length)
    except PasswordLengthError as e:
        return None, False, Response.json({"ok": False, "error": str(e)}, status=400)
    return provided, False, None


@router.POST("/-/admin/api/list$")
@require_admin
async def admin_list(datasette, request):
    internal = datasette.get_internal_database()
    rows = await db.list_users(internal)
    users = [UserRow(**db.to_user_row(r)).model_dump() for r in rows]
    return Response.json({"ok": True, "users": users})


@router.POST("/-/admin/api/create$", output=None)
@require_admin
async def admin_create(datasette, request, body: Annotated[CreateUserRequest, Body()]):
    internal = datasette.get_internal_database()
    plaintext, generated, error = _resolve_password(
        datasette, body.password, body.generate
    )
    if error:
        return error
    password_hash = await ahash_password(plaintext)
    try:
        user_id = await db.create_user(
            internal,
            request.actor["id"],
            body.username,
            password_hash,
            body.is_admin,
            body.must_change_password,
        )
    except db.UsernameTakenError:
        return Response.json(
            {"ok": False, "error": "Username already taken"}, status=409
        )
    result = {"ok": True, "id": user_id}
    if generated:
        result["password"] = plaintext
    return Response.json(result)


@router.POST("/-/admin/api/reset-password$")
@require_admin
async def admin_reset_password(
    datasette, request, body: Annotated[ResetPasswordRequest, Body()]
):
    internal = datasette.get_internal_database()
    plaintext, generated, error = _resolve_password(
        datasette, body.password, body.generate
    )
    if error:
        return error
    # A manually-supplied reset must differ from the target's current password.
    # (A generated one is random — skip the extra KDF verify.)
    if not generated:
        target = await db.get_user_by_id(internal, body.id)
        if target and await averify_password(plaintext, target["password_hash"]):
            return Response.json(
                {
                    "ok": False,
                    "error": "New password must be different from the current one",
                },
                status=400,
            )
    password_hash = await ahash_password(plaintext)
    await db.reset_password(internal, request.actor["id"], body.id, password_hash)
    result = {"ok": True}
    if generated:
        result["password"] = plaintext
    return Response.json(result)


@router.POST("/-/admin/api/toggle-admin$")
@require_admin
async def admin_toggle_admin(
    datasette, request, body: Annotated[TargetRequest, Body()]
):
    internal = datasette.get_internal_database()
    try:
        await db.toggle_admin(internal, request.actor["id"], body.id)
    except db.LastAdminError:
        return Response.json(
            {"ok": False, "error": "Cannot demote the last admin"}, status=409
        )
    return Response.json({"ok": True})


@router.POST("/-/admin/api/disable$")
@require_admin
async def admin_disable(datasette, request, body: Annotated[TargetRequest, Body()]):
    internal = datasette.get_internal_database()
    try:
        await db.disable_user(internal, request.actor["id"], body.id)
    except db.LastAdminError:
        return Response.json(
            {"ok": False, "error": "Cannot disable the last admin"}, status=409
        )
    return Response.json({"ok": True})


@router.POST("/-/admin/api/enable$")
@require_admin
async def admin_enable(datasette, request, body: Annotated[TargetRequest, Body()]):
    internal = datasette.get_internal_database()
    await db.enable_user(internal, request.actor["id"], body.id)
    return Response.json({"ok": True})


@router.POST("/-/admin/api/delete$")
@require_admin
async def admin_delete(datasette, request, body: Annotated[TargetRequest, Body()]):
    internal = datasette.get_internal_database()
    try:
        await db.delete_user(internal, request.actor["id"], body.id)
    except db.LastAdminError:
        return Response.json(
            {"ok": False, "error": "Cannot delete the last admin"}, status=409
        )
    return Response.json({"ok": True})


@router.POST("/-/admin/api/unlock$")
@require_admin
async def admin_unlock(datasette, request, body: Annotated[TargetRequest, Body()]):
    internal = datasette.get_internal_database()
    await db.unlock_user(internal, request.actor["id"], body.id)
    return Response.json({"ok": True})


@router.POST("/-/admin/api/list-sessions$")
@require_admin
async def admin_list_sessions(
    datasette, request, body: Annotated[TargetRequest, Body()]
):
    internal = datasette.get_internal_database()
    rows = await db.list_sessions_for_user(internal, body.id)
    sessions = [
        SessionRow(**{k: r.get(k) for k in SessionRow.model_fields}) for r in rows
    ]
    return Response.json({"ok": True, "sessions": [s.model_dump() for s in sessions]})


@router.POST("/-/admin/api/revoke-session$")
@require_admin
async def admin_revoke_session(
    datasette, request, body: Annotated[RevokeSessionRequest, Body()]
):
    internal = datasette.get_internal_database()
    await db.revoke_session(internal, request.actor["id"], body.id, body.token_sha256)
    return Response.json({"ok": True})


@router.POST("/-/admin/api/logout-everywhere$")
@require_admin
async def admin_logout_everywhere(
    datasette, request, body: Annotated[TargetRequest, Body()]
):
    internal = datasette.get_internal_database()
    await db.logout_everywhere(internal, request.actor["id"], body.id)
    return Response.json({"ok": True})


@router.POST("/-/admin/api/login-attempts$")
@require_admin
async def admin_login_attempts(
    datasette, request, body: Annotated[LoginAttemptsRequest, Body()]
):
    internal = datasette.get_internal_database()
    rows = await db.list_login_attempts(
        internal, body.username or None, body.ip or None
    )
    attempts = [
        LoginAttemptRow(**{k: r.get(k) for k in LoginAttemptRow.model_fields})
        for r in rows
    ]
    return Response.json({"ok": True, "attempts": [a.model_dump() for a in attempts]})


# --------------------------------------------------------------------------
# Capability grants (F1) — grant global actions to accounts/groups/audiences
# --------------------------------------------------------------------------


@router.POST("/-/admin/api/capabilities/list$")
@require_admin
async def admin_capabilities_list(datasette, request):
    internal = datasette.get_internal_database()
    view = await grantable.grantable_view(datasette, internal)
    return Response.json({"ok": True, **view})


@router.POST("/-/admin/api/capabilities/grant$")
@require_admin
async def admin_capabilities_grant(
    datasette, request, body: Annotated[GrantCapabilityRequest, Body()]
):
    internal = datasette.get_internal_database()
    # Only grant currently-grantable global actions.
    if not grantable.is_grantable(datasette, body.action):
        return Response.json(
            {"ok": False, "error": "Action is not grantable"}, status=400
        )
    # Enforce principal gating (group availability + public-audience rules, D11).
    has_acl = await db.acl_available(internal)
    if not grantable.principal_offerable(
        datasette, body.action, body.principal_type, has_acl
    ):
        return Response.json(
            {"ok": False, "error": "Principal not allowed for this action"},
            status=400,
        )
    try:
        await db.grant_capability(
            internal,
            request.actor["id"],
            action=body.action,
            principal_type=body.principal_type,
            target_actor_id=body.actor_id,
            group_id=body.group_id,
        )
    except db.InvalidGrantError as e:
        return Response.json({"ok": False, "error": str(e)}, status=400)
    return Response.json({"ok": True})


@router.POST("/-/admin/api/capabilities/revoke$")
@require_admin
async def admin_capabilities_revoke(
    datasette, request, body: Annotated[RevokeCapabilityRequest, Body()]
):
    internal = datasette.get_internal_database()
    await db.revoke_capability(internal, request.actor["id"], body.id)
    return Response.json({"ok": True})


# --------------------------------------------------------------------------
# Site messages (admin-editable help text surfaced in the app)
# --------------------------------------------------------------------------


@router.POST("/-/admin/api/messages/list$")
@require_admin
async def admin_messages_list(datasette, request):
    internal = datasette.get_internal_database()
    view = await messages.slots_view(internal)
    return Response.json({"ok": True, **view})


@router.POST("/-/admin/api/messages/set$")
@require_admin
async def admin_messages_set(
    datasette, request, body: Annotated[SetSiteMessageRequest, Body()]
):
    if not messages.is_slot(body.key):
        return Response.json({"ok": False, "error": "Unknown message"}, status=400)
    if len(body.body) > messages.MAX_BODY_LENGTH:
        return Response.json({"ok": False, "error": "Message is too long"}, status=400)
    internal = datasette.get_internal_database()
    stored = await db.set_site_message(
        internal, request.actor["id"], body.key, body.body
    )
    return Response.json({"ok": True, "body": stored})
