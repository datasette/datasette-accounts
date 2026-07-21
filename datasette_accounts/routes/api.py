"""JSON API endpoints: authenticate, logout, change-password, admin operations."""

from typing import Annotated

from datasette import Response
from datasette_plugin_router import Body

from .. import db, grantable, messages, security
from ..page_data import (
    AdminAuditRequest,
    AdminAuditRow,
    AuthenticateRequest,
    ChangePasswordRequest,
    CompleteSetPasswordRequest,
    CreateUserRequest,
    GrantCapabilityRequest,
    InviteRequest,
    LoginAttemptRow,
    LoginAttemptsRequest,
    RegisterRequest,
    ResetPasswordRequest,
    RevokeCapabilityRequest,
    RevokeOwnSessionRequest,
    RevokeSessionRequest,
    SessionRow,
    SetExpiryRequest,
    SetRegistrationRequest,
    SetSiteMessageRequest,
    TargetRequest,
    UserRow,
)
from ..passwords import (
    PasswordLengthError,
    ahash_password,
    averify_password,
    check_password_length,
    generate_password,
)

# Re-exported so providers.password.verify_credentials can reach the KDF through
# this module (the timing-discipline tests monkeypatch api.averify_dummy, so the
# verify half must call it via the api module rather than its own binding).
from ..passwords import averify_dummy  # noqa: F401
from ..providers import (
    LocalIdentity,
    clear_stale_core_actor_cookie,
    finish_login,
    mint_session,
)
from ..providers import password
from ..router import require_actor, require_admin, require_csrf, router
from ..security import COOKIE_NAME
from ..sessions import current_token_sha, list_own_sessions, mint_token, token_sha256


# --------------------------------------------------------------------------
# Login / logout
# --------------------------------------------------------------------------


@router.POST("/-/login/api/authenticate$")
@require_csrf
async def authenticate(
    datasette, request, body: Annotated[AuthenticateRequest, Body()]
):
    # Thin wrapper (design §8): the password provider owns the verify half; the
    # single mint chokepoint (finish_login) owns the success half. Path unchanged.
    result = await password.verify_credentials(
        datasette, request, body.username, body.password
    )
    if isinstance(result, Response):
        # A 429/401 error response to send verbatim (verify already audited it).
        return result
    # Verify passed → mint through finish_login. `next` is threaded via the
    # state dict so finish_login re-validates it server-side, exactly as before.
    return await finish_login(
        datasette,
        request,
        LocalIdentity(result["id"]),
        provider_key="password",
        response_mode="json",
        state={"n": body.next},
    )


@router.POST("/-/logout/perform$")
@require_csrf
async def logout(datasette, request):
    internal = datasette.get_internal_database()
    token_sha = current_token_sha(datasette, request)
    if token_sha:
        await db.delete_session(internal, token_sha)
    response = Response.json({"ok": True, "redirect": "/"})
    response.set_cookie(COOKIE_NAME, "", max_age=0, path="/", expires=0)
    clear_stale_core_actor_cookie(request, response)
    return response


# --------------------------------------------------------------------------
# Self-registration (see plans/self-registration)
# --------------------------------------------------------------------------


@router.POST("/-/register/api/submit$")
@require_csrf
async def register_submit(datasette, request, body: Annotated[RegisterRequest, Body()]):
    # Thin wrapper (design §8): the register logic lives with the password
    # provider. Path unchanged.
    return await password.register(datasette, request, body)


# --------------------------------------------------------------------------
# Set-password links (invite / reset) — see plans/invite-links
# --------------------------------------------------------------------------


@router.POST("/-/set-password/api/complete$")
@require_csrf
async def set_password_complete(
    datasette, request, body: Annotated[CompleteSetPasswordRequest, Body()]
):
    internal = datasette.get_internal_database()
    ip = security.client_ip(datasette, request)

    # The length check MUST precede the claim: a password that's simply too
    # short must not burn the (single-use) link.
    try:
        check_password_length(
            body.new_password, security.config(datasette, "password_min_length")
        )
    except PasswordLengthError as e:
        return Response.json({"ok": False, "error": str(e)}, status=400)

    new_hash = await ahash_password(body.new_password)
    user_id = await db.use_password_token(internal, token_sha256(body.token), new_hash)
    if user_id is None:
        await db.record_login_attempt(internal, None, ip, False, "bad_token")
        return Response.json(
            {"ok": False, "error": "This link is invalid or has expired"}, status=400
        )

    user = await db.get_user_by_id(internal, user_id)
    # Mirror authenticate(): disabled, expired, and pending accounts never get
    # signed in (and never reach record_login_success, which would clear the
    # lockout counters). The password is still set and every session revoked —
    # the link proved control of the account — but a session minted here would
    # outlive the blocked state (e.g. spring back to life when an admin later
    # clears the expiry).
    expired = bool(user and user["expires_at"] and user["expires_at"] <= db.now_iso())
    if not user or user["disabled"] or expired or user["pending_approval"]:
        return Response.json({"ok": True, "redirect": datasette.urls.path("/-/login")})

    # Otherwise: the link just proved control of the account — sign them in
    # exactly like a successful authenticate() call. We build the historical
    # response and mint through the shared chokepoint (providers.mint_session),
    # NOT finish_login: finish_login's JSON body adds a must_change_password key,
    # which would change this endpoint's long-standing {"ok", "redirect"} shape.
    response = Response.json({"ok": True, "redirect": "/"})
    await mint_session(datasette, request, response, user)
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
        internal, user["id"], new_hash, current_token_sha(datasette, request)
    )
    return Response.json({"ok": True})


@router.POST("/-/account/api/sessions$")
@require_actor
async def account_sessions(datasette, request):
    internal = datasette.get_internal_database()
    sessions = await list_own_sessions(
        datasette, request, internal, request.actor["id"]
    )
    return Response.json({"ok": True, "sessions": [s.model_dump() for s in sessions]})


@router.POST("/-/account/api/revoke-session$")
@require_actor
async def account_revoke_session(
    datasette, request, body: Annotated[RevokeOwnSessionRequest, Body()]
):
    internal = datasette.get_internal_database()
    # The current session ends via the normal logout path (which also clears
    # the cookie) — revoking the session you're browsing with is a footgun.
    if body.token_sha256 == current_token_sha(datasette, request):
        return Response.json(
            {"ok": False, "error": "Use log out for this device"}, status=400
        )
    actor_id = request.actor["id"]
    # Scoped to self: the actor-scoped DELETE no-ops on tokens belonging to
    # anyone else. We report ok either way — distinguishing would hand callers
    # an oracle for whether an arbitrary token hash exists on another account.
    await db.revoke_session(internal, actor_id, actor_id, body.token_sha256)
    return Response.json({"ok": True})


@router.POST("/-/account/api/logout-others$")
@require_actor
async def account_logout_others(datasette, request):
    token_sha = current_token_sha(datasette, request)
    if not token_sha:
        # Shouldn't happen for an actor-holding request, but never let a
        # missing "current" turn keep-my-session into delete-everything.
        return Response.json(
            {"ok": False, "error": "Authentication required"}, status=401
        )
    internal = datasette.get_internal_database()
    await db.logout_other_sessions(internal, request.actor["id"], token_sha)
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
    rows = await db.list_user_rows(internal)
    users = [UserRow(**r).model_dump() for r in rows]
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


def _set_password_url(datasette, request, raw_token):
    # The raw token is `secrets.token_urlsafe` (base64url charset), so plain
    # concatenation onto the query string is safe — no encoding needed.
    path = datasette.urls.path("/-/set-password") + "?token=" + raw_token
    return datasette.absolute_url(request, path)


@router.POST("/-/admin/api/invite$")
@require_admin
async def admin_invite(datasette, request, body: Annotated[InviteRequest, Body()]):
    internal = datasette.get_internal_database()
    raw_token = mint_token()
    ttl_hours = security.config(datasette, "invite_ttl_hours")
    try:
        user_id = await db.create_invited_user(
            internal,
            request.actor["id"],
            body.username,
            body.is_admin,
            token_sha256(raw_token),
            ttl_hours,
        )
    except db.UsernameTakenError:
        return Response.json(
            {"ok": False, "error": "Username already taken"}, status=409
        )
    return Response.json(
        {
            "ok": True,
            "id": user_id,
            "url": _set_password_url(datasette, request, raw_token),
        }
    )


async def _mint_link_response(datasette, request, target_id, purpose, ttl_hours):
    """Shared invite-link / reset-link body: mint + one-time absolute URL."""
    internal = datasette.get_internal_database()
    raw_token = mint_token()
    minted = await db.mint_password_token(
        internal,
        request.actor["id"],
        target_id,
        purpose,
        token_sha256(raw_token),
        ttl_hours,
    )
    if not minted:
        return Response.json({"ok": False, "error": "Unknown account"}, status=404)
    return Response.json(
        {"ok": True, "url": _set_password_url(datasette, request, raw_token)}
    )


@router.POST("/-/admin/api/invite-link$")
@require_admin
async def admin_invite_link(datasette, request, body: Annotated[TargetRequest, Body()]):
    """Re-mint an invite link for an existing account (kills the prior link).

    Meaningful for accounts that never set a password, but the endpoint
    doesn't enforce that — minting always kills the account's prior
    outstanding link regardless of purpose (D: one live link per account).
    """
    return await _mint_link_response(
        datasette,
        request,
        body.id,
        "invite",
        security.config(datasette, "invite_ttl_hours"),
    )


@router.POST("/-/admin/api/reset-link$")
@require_admin
async def admin_reset_link(datasette, request, body: Annotated[TargetRequest, Body()]):
    """Mint a one-time reset link for an existing account.

    Minting does NOT revoke the account's live sessions — the user stays
    signed in until the link is actually used (completion revokes everything
    and signs them in fresh).
    """
    return await _mint_link_response(
        datasette,
        request,
        body.id,
        "reset",
        security.config(datasette, "reset_link_ttl_hours"),
    )


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
    # Deliberately NO differs-from-current check here (unlike change_password):
    # verifying an admin-supplied plaintext against the target's stored hash
    # would hand admins an oracle for testing guesses against a user's real
    # password. Resetting to the same value is harmless anyway — sessions and
    # outstanding links are still revoked.
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


@router.POST("/-/admin/api/approve$")
@require_admin
async def admin_approve(datasette, request, body: Annotated[TargetRequest, Body()]):
    """Approve a pending self-registered account (see plans/self-registration)."""
    internal = datasette.get_internal_database()
    if not await db.approve_user(internal, request.actor["id"], body.id):
        return Response.json({"ok": False, "error": "Unknown account"}, status=404)
    return Response.json({"ok": True})


@router.POST("/-/admin/api/reject$")
@require_admin
async def admin_reject(datasette, request, body: Annotated[TargetRequest, Body()]):
    """Reject (delete) a pending self-registered account.

    Refusing non-pending targets with a 400 means a mis-aimed reject can
    never delete an active user — deleting those is admin_delete's job.
    """
    internal = datasette.get_internal_database()
    try:
        rejected = await db.reject_user(internal, request.actor["id"], body.id)
    except db.NotPendingError:
        return Response.json(
            {"ok": False, "error": "Account is not awaiting approval"}, status=400
        )
    if not rejected:
        return Response.json({"ok": False, "error": "Unknown account"}, status=404)
    return Response.json({"ok": True})


@router.POST("/-/admin/api/set-expiry$")
@require_admin
async def admin_set_expiry(
    datasette, request, body: Annotated[SetExpiryRequest, Body()]
):
    """Set, extend, or clear an account's expiry deadline.

    All timestamp handling lives in db.set_user_expiry (which resolves the
    stored value in SQL) — this route only maps errors to statuses. Clearing
    (neither value form supplied) needs no last-admin guard.
    """
    if body.expires_at is not None and body.in_days is not None:
        return Response.json(
            {"ok": False, "error": "Provide either expires_at or in_days, not both"},
            status=400,
        )
    internal = datasette.get_internal_database()
    try:
        result = await db.set_user_expiry(
            internal,
            request.actor["id"],
            body.id,
            at=body.expires_at,
            in_days=body.in_days,
        )
    except db.InvalidExpiryError:
        return Response.json(
            {"ok": False, "error": "Expiry must be a valid timestamp in the future"},
            status=400,
        )
    except db.LastAdminError:
        return Response.json(
            {"ok": False, "error": "Cannot set an expiry on the last admin"},
            status=409,
        )
    if result is False:  # unknown target id (None means a successful clear)
        return Response.json({"ok": False, "error": "Unknown account"}, status=404)
    return Response.json({"ok": True, "expires_at": result})


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


async def audit_entries(internal, username, operation):
    """Filtered admin-audit rows as AdminAuditRow models.

    Shared by the audit page and its API endpoint so the two can't drift.
    Filtering by username resolves to a target id here in the route layer; an
    unknown username yields an empty result rather than an error (the account
    may have been deleted — its history is then reachable via operation
    filters and detail text).
    """
    target_id = None
    if username:
        user = await db.get_user_by_username(internal, username)
        if user is None:
            return []
        target_id = user["id"]
    rows = await db.list_admin_audit(internal, target_id, operation or None)
    return [
        AdminAuditRow(**{k: r.get(k) for k in AdminAuditRow.model_fields}) for r in rows
    ]


@router.POST("/-/admin/api/audit$")
@require_admin
async def admin_audit(datasette, request, body: Annotated[AdminAuditRequest, Body()]):
    internal = datasette.get_internal_database()
    entries = await audit_entries(internal, body.username, body.operation)
    return Response.json({"ok": True, "entries": [e.model_dump() for e in entries]})


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


# --------------------------------------------------------------------------
# Self-registration toggle (see plans/self-registration)
# --------------------------------------------------------------------------


@router.POST("/-/admin/api/set-registration$")
@require_admin
async def admin_set_registration(
    datasette, request, body: Annotated[SetRegistrationRequest, Body()]
):
    """Flip the runtime signups toggle. Takes effect on the very next request
    to /-/register — nothing about the toggle is cached."""
    internal = datasette.get_internal_database()
    enabled = await db.set_registration_enabled(
        internal, request.actor["id"], body.enabled
    )
    return Response.json({"ok": True, "enabled": enabled})
