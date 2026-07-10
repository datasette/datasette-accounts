"""Pluggable sign-in providers: the contract, signed state, and finish_login.

Providers authenticate; datasette-accounts owns identity, policy, and sessions
(plans/auth-providers/02-design.md §§1–4). A provider's `handle()` serves its
own URL surface under `/-/login/provider/{key}/*` and ends every flow by
returning `await finish_login(...)` — the single termination point that runs
the account gates and mints the session. Core owns the signed OAuth `state` so
no provider hand-rolls it.
"""

import re
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from datasette import Response

from .. import db, security
from ..security import COOKIE_NAME, SIGN_NAMESPACE
from ..sessions import mint_token, token_sha256

# Provider keys: lowercase slug, must start with an alphanumeric. "password" is
# reserved for the built-in provider; it matches KEY_RE like any other key, so
# the registry validates it the same way and simply rejects a *duplicate*.
KEY_RE = re.compile(r"^[a-z0-9][a-z0-9-]*$")

# Signed-state cookie + namespace, and the attribute the registry lives on.
STATE_COOKIE = "ds_accounts_state"
STATE_NAMESPACE = "datasette-accounts-state"
REGISTRY_ATTR = "_datasette_accounts_providers"

# Shown to the visitor when finish_login refuses. Deliberately generic: it must
# never distinguish "disabled" from "expired" from "pending" (the specific
# reason lives only in the admin-only login_audit).
GENERIC_FLOW_ERROR = "Unable to sign in"


class AuthProvider:
    """Base class for a sign-in provider (see design §2).

    Subclasses set ``key`` (KEY_RE; unique; "password" reserved for the
    built-in) and ``label`` (e.g. "GitHub", rendered as "Continue with
    {label}") and implement ``handle``.
    """

    key: str
    label: str

    async def handle(self, datasette, request, subpath: str):
        """Serve one request under /-/login/provider/{key}/{subpath}.

        Conventional subpaths: "start" (begin the flow) and "callback".
        A flow ends by returning ``await finish_login(...)``.
        """
        raise NotImplementedError


@dataclass(frozen=True)
class LocalIdentity:
    user_id: str  # an existing datasette_accounts_users.id


@dataclass(frozen=True)
class ExternalIdentity:
    provider: str  # must equal the calling provider's key
    subject: str  # the IdP's *stable* user id — never an email
    email: str | None = None
    email_verified: bool = False
    username_hint: str | None = None  # e.g. the gh login — provisioning only
    display_name: str | None = None  # audit detail only; we store no profile


# The built-in username/password provider lives in providers/password.py so the
# login/register/set-password code it owns can move there without a circular
# import against this module's finish_login.


# --------------------------------------------------------------------------
# Signed state — core-owned, provider-consumed (design §2)
# --------------------------------------------------------------------------


def make_state(
    datasette,
    request,
    response,
    *,
    provider,
    next=None,
    intent="login",
    actor_id=None,
    step_up=None,
):
    """Mint a signed OAuth `state`, set the state cookie, return the value.

    `request` is needed only to decide the cookie's Secure flag. `next` is
    validated at creation time (and again when the state is consumed) — the
    same belt-and-braces as today's login flow.
    """
    base_url = datasette.setting("base_url") or "/"
    value = secrets.token_urlsafe(16)
    payload = {
        "s": value,
        "p": provider,
        "n": security.validate_next(next, base_url),
        "i": intent,
        "a": actor_id,
        "u": step_up,
        "c": db.now_iso(),
    }
    ttl_minutes = security.config(datasette, "provider_state_ttl_minutes")
    response.set_cookie(
        STATE_COOKIE,
        datasette.sign(payload, STATE_NAMESPACE),
        max_age=60 * ttl_minutes,
        path="/",
        httponly=True,
        samesite="lax",
        secure=security.should_secure_cookie(datasette, request),
    )
    return value


def read_state(datasette, request, *, provider):
    """Validate + return the signed state payload, or None on any failure.

    Requires: a well-signed cookie; the `state` query arg matching the stored
    value (double-submit); the provider key matching; and `created` within the
    TTL window. Any failure → None (the caller shows the generic flow-failed
    page and clears the cookie).
    """
    cookie = request.cookies.get(STATE_COOKIE)
    if not cookie:
        return None
    try:
        payload = datasette.unsign(cookie, STATE_NAMESPACE)
    except Exception:
        # Any unsign failure (bad signature, malformed value, wrong type) is
        # treated as "no valid state" — never a 500. Mirrors resolve_actor's
        # broad guard around unsign in __init__.py.
        return None
    if not isinstance(payload, dict):
        return None
    # Double-submit: the `state` query arg must equal the value in the cookie.
    if not secrets.compare_digest(
        request.args.get("state") or "", payload.get("s") or ""
    ):
        return None
    if payload.get("p") != provider:
        return None
    # `created` must be newer than ttl_minutes ago. The cutoff is formatted like
    # db.now_iso() (millisecond ISO + offset), so the comparison is lexicographic
    # — the repo-wide timestamp convention.
    ttl_minutes = security.config(datasette, "provider_state_ttl_minutes")
    cutoff = (datetime.now(timezone.utc) - timedelta(minutes=ttl_minutes)).isoformat(
        timespec="milliseconds"
    )
    created = payload.get("c")
    if not created or created <= cutoff:
        return None
    return payload


def clear_state_cookie(response):
    response.set_cookie(STATE_COOKIE, "", max_age=0, path="/", expires=0)


# --------------------------------------------------------------------------
# Session cookie (moved verbatim from routes/api.py)
# --------------------------------------------------------------------------


def set_session_cookie(datasette, request, response, raw_token):
    response.set_cookie(
        COOKIE_NAME,
        datasette.sign(raw_token, SIGN_NAMESPACE),
        max_age=security.config(datasette, "session_ttl_days") * 86400,
        path="/",
        httponly=True,
        samesite="lax",
        secure=security.should_secure_cookie(datasette, request),
    )


def clear_stale_core_actor_cookie(request, response):
    # This plugin owns auth via its own session cookie, but a leftover core
    # `ds_actor` cookie (e.g. an old root login) makes Datasette's base
    # template render its own Log out button next to ours. Signing in or out
    # through our flows asserts accounts-based identity, so drop the stale
    # core cookie whenever it is present. (Moved here from routes/api.py so
    # every mint path — including finish_login — evicts it uniformly.)
    if "ds_actor" in request.cookies:
        response.set_cookie("ds_actor", "", max_age=0, path="/", expires=0)


async def mint_session(datasette, request, response, user):
    """The single session mint: stamp login success, create the session row,
    and set the session + stale-core cookies on ``response``.

    This is exactly authenticate()'s historical success half minus the periodic
    housekeeping, so callers that want housekeeping (finish_login) run it around
    this and callers that never did (set-password completion) don't. The one
    ``db.create_session`` call in the plugin lives here.
    """
    internal = datasette.get_internal_database()
    ip = security.client_ip(datasette, request)
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
    set_session_cookie(datasette, request, response, raw_token)
    clear_stale_core_actor_cookie(request, response)


# --------------------------------------------------------------------------
# finish_login — the single termination point (design §4)
# --------------------------------------------------------------------------


async def finish_login(
    datasette,
    request,
    identity,
    *,
    provider_key,
    response_mode="redirect",
    state=None,
):
    """Terminate a sign-in flow: run account gates, then mint the session.

    `provider_key` is the key of the provider that produced `identity` (carried
    for the provenance column ticket 03 adds; unused here). This ticket handles
    LocalIdentity only; ExternalIdentity raises NotImplementedError (ticket 03).
    """
    if isinstance(identity, LocalIdentity):
        return await _finish_local(
            datasette,
            request,
            identity,
            response_mode=response_mode,
            state=state,
        )
    if isinstance(identity, ExternalIdentity):
        raise NotImplementedError(
            "ExternalIdentity is implemented in a later milestone (ticket 03)"
        )
    raise TypeError(f"Unknown identity type: {type(identity)!r}")


async def _finish_local(datasette, request, identity, *, response_mode, state):
    internal = datasette.get_internal_database()
    ip = security.client_ip(datasette, request)
    user = await db.get_user_by_id(internal, identity.user_id)

    # Same gates, same precedence as authenticate(): disabled > expired >
    # pending_approval. (The password verify — and its gate routing — already
    # ran in the caller; this is the shared, defense-in-depth chokepoint.)
    expired = bool(user and user["expires_at"] and user["expires_at"] <= db.now_iso())
    if user is None:
        reason = "no_such_user"
    elif user["disabled"]:
        reason = "disabled"
    elif expired:
        reason = "expired"
    elif user["pending_approval"]:
        reason = "pending_approval"
    else:
        reason = None

    if reason is not None:
        await db.record_login_attempt(
            internal, user["username"] if user else None, ip, False, reason
        )
        return _refuse(response_mode)

    base_url = datasette.setting("base_url") or "/"
    # `next` from the state was validated when the state was created; re-validate
    # on consumption (belt and braces).
    next_value = state.get("n") if state else None
    redirect = security.validate_next(next_value, base_url)

    if response_mode == "json":
        response = Response.json(
            {
                "ok": True,
                "redirect": redirect,
                "must_change_password": bool(user["must_change_password"]),
            }
        )
    else:
        response = Response.redirect(redirect)

    # Mint — identical to authenticate()'s success half (mint + the periodic
    # housekeeping it runs). mint_session sets the session + stale-core cookies.
    await mint_session(datasette, request, response, user)
    await db.delete_expired_sessions(internal)
    await db.purge_expired_password_tokens(internal)
    await db.purge_login_audit(
        internal, security.config(datasette, "audit_retention_days")
    )
    await db.purge_admin_audit(
        internal, security.config(datasette, "admin_audit_retention_days")
    )
    clear_state_cookie(response)
    return response


def _refuse(response_mode):
    if response_mode == "json":
        response = Response.json({"ok": False, "error": GENERIC_FLOW_ERROR}, status=403)
    else:
        response = Response.html(
            f"<h1>Sign-in failed</h1><p>{GENERIC_FLOW_ERROR}</p>", status=403
        )
    clear_state_cookie(response)
    return response
