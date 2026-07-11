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
from urllib.parse import quote

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
# Registry access + presentation helpers
# --------------------------------------------------------------------------


def get_registry(datasette):
    """The provider registry dict {key: AuthProvider} built at startup (§3)."""
    return getattr(datasette, REGISTRY_ATTR, {})


def provider_label(datasette, key):
    """Display label for a provider key, falling back to the key when the
    provider package is no longer installed (a linked identity outliving its
    provider still renders)."""
    provider = get_registry(datasette).get(key)
    return provider.label if provider is not None else key


def external_provider_keys(datasette):
    """Every installed external provider key (registry order, `password`
    excluded) — the universe the account page filters to 'linkable'."""
    return [k for k in get_registry(datasette) if k != "password"]


def to_identity_rows(datasette, raw_identities):
    """Map db identity dicts → IdentityRow-shaped dicts, resolving the display
    label from the live registry. Shared by the account + admin surfaces."""
    return [
        {
            "provider": i["provider"],
            "label": provider_label(datasette, i["provider"]),
            "subject": i["subject"],
            "created_at": i["created_at"],
            "last_login_at": i.get("last_login_at"),
        }
        for i in raw_identities
    ]


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


async def mint_session(datasette, request, response, user, provider="password"):
    """The single session mint: stamp login success, create the session row,
    and set the session + stale-core cookies on ``response``.

    This is exactly authenticate()'s historical success half minus the periodic
    housekeeping, so callers that want housekeeping (finish_login) run it around
    this and callers that never did (set-password completion) don't. The one
    ``db.create_session`` call in the plugin lives here. ``provider`` is stamped
    on the session row as provenance (which provider minted it — 'password' for
    the built-in flow, the external provider's key otherwise).
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
        provider=provider,
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
    """Terminate a sign-in flow: run account gates + policy, then mint.

    `provider_key` is the key of the provider that produced `identity`; it is
    stamped on the session + login_audit rows as provenance. LocalIdentity
    (password / invite / reset completion) loads the user directly;
    ExternalIdentity maps `(provider, subject)` through the identities table and
    applies the per-provider signups policy for an unmatched identity.
    """
    if isinstance(identity, LocalIdentity):
        return await _finish_local(
            datasette,
            request,
            identity,
            provider_key=provider_key,
            response_mode=response_mode,
            state=state,
        )
    if isinstance(identity, ExternalIdentity):
        return await _finish_external(
            datasette,
            request,
            identity,
            provider_key=provider_key,
            response_mode=response_mode,
            state=state,
        )
    raise TypeError(f"Unknown identity type: {type(identity)!r}")


def _gate_reason(user, *, external):
    """Shared account gate for both identity kinds — disabled > expired >
    pending_approval precedence. Returns a login_audit reason string, or None
    when the account may sign in. External flows use the `provider_*` reasons so
    the admin audit distinguishes an SSO refusal from a password one."""
    expired = bool(user and user["expires_at"] and user["expires_at"] <= db.now_iso())
    if user is None:
        return "provider_no_account" if external else "no_such_user"
    if user["disabled"]:
        return "provider_disabled" if external else "disabled"
    if expired:
        return "provider_expired" if external else "expired"
    if user["pending_approval"]:
        return "provider_pending" if external else "pending_approval"
    return None


async def _finish_local(datasette, request, identity, *, provider_key, response_mode, state):
    internal = datasette.get_internal_database()
    ip = security.client_ip(datasette, request)
    user = await db.get_user_by_id(internal, identity.user_id)

    # Same gates, same precedence as authenticate(): disabled > expired >
    # pending_approval. (The password verify — and its gate routing — already
    # ran in the caller; this is the shared, defense-in-depth chokepoint. The
    # success login_audit row is the verify half's job, so we write only
    # refusals here — untouched division of labor.)
    reason = _gate_reason(user, external=False)
    if reason is not None:
        await db.record_login_attempt(
            internal, user["username"] if user else None, ip, False, reason
        )
        return _refuse(response_mode)

    return await _mint_and_respond(
        datasette,
        request,
        user,
        provider_key=provider_key,
        response_mode=response_mode,
        state=state,
    )


async def _finish_external(
    datasette, request, identity, *, provider_key, response_mode, state
):
    # A provider handing back another provider's identity is a bug, not a
    # runtime condition — fail loud (500), never silently map across providers.
    assert identity.provider == provider_key, (
        f"provider {provider_key!r} returned identity for {identity.provider!r}"
    )
    internal = datasette.get_internal_database()
    ip = security.client_ip(datasette, request)

    # Defense in depth: the mount already checked the enabled bit, but a
    # provider could call finish_login from anywhere. A disabled provider can
    # never mint.
    if not await db.get_provider_enabled(internal, provider_key):
        await db.record_login_attempt(
            internal, None, ip, False, "provider_disabled", provider=provider_key
        )
        return _refuse(response_mode)

    existing = await db.get_identity(internal, provider_key, identity.subject)
    intent = (state or {}).get("i") or "login"

    # Linking intents (design §6) are handled BEFORE the login mint: a link /
    # step-up flow must NEVER mint a session for the identity's owner — the user
    # is already signed in throughout linking, and treating a link callback as a
    # login would let an attacker who completes a link flow with a *victim's*
    # already-linked identity be signed in as that victim. The found/not-found
    # split is delegated so each intent decides explicitly.
    if intent == "step-up":
        return await _finish_step_up(
            datasette, request, identity, existing,
            provider_key=provider_key, response_mode=response_mode, state=state,
        )
    if intent == "link":
        return await _finish_link(
            datasette, request, identity, existing,
            provider_key=provider_key, response_mode=response_mode, state=state,
        )

    # intent == "login" from here down.
    if existing is not None:
        # Linked → load the account, run the same gates as a password login.
        user = await db.get_user_by_id(internal, existing["user_id"])
        reason = _gate_reason(user, external=True)
        if reason is not None:
            await db.record_login_attempt(
                internal,
                user["username"] if user else None,
                ip,
                False,
                reason,
                provider=provider_key,
            )
            return _refuse(response_mode)
        await db.touch_identity_login(internal, provider_key, identity.subject)
        return await _mint_external(
            datasette,
            request,
            user,
            provider_key=provider_key,
            response_mode=response_mode,
            state=state,
        )

    # Unmatched identity, intent == "login": consult the provider's signups policy.
    signups = await db.get_provider_signups(internal, provider_key)
    if signups == "off":
        # Generic — identical wording whether signups are off or the identity is
        # simply unknown, so a visitor can't probe which providers auto-link.
        await db.record_login_attempt(
            internal, None, ip, False, "provider_no_account", provider=provider_key
        )
        return _refuse_no_account(response_mode)

    if signups == "approval":
        return await _provision_pending(
            datasette, request, identity, provider_key=provider_key,
            response_mode=response_mode,
        )

    # signups == "auto" (auto-activate — for trusted IdPs): create active + mint.
    user_id = await db.provision_external_user(internal, identity, ip, pending=False)
    user = await db.get_user_by_id(internal, user_id)
    await db.touch_identity_login(internal, provider_key, identity.subject)
    return await _mint_external(
        datasette,
        request,
        user,
        provider_key=provider_key,
        response_mode=response_mode,
        state=state,
    )


# --------------------------------------------------------------------------
# Linking + step-up (design §6) — reached only for link / step-up intents,
# which never mint a session (the user is already signed in throughout linking).
# --------------------------------------------------------------------------


async def _finish_step_up(
    datasette, request, identity, existing, *, provider_key, response_mode, state
):
    """Step-up proof: the acting user re-completed an ALREADY-linked provider's
    flow (the password-less step-up path, design D8). The presented identity must
    be found AND owned by the state's bound actor. On success we do NOT mint —
    we 302 into the *target* provider's start with a fresh ``intent="link"`` state
    carrying the step-up proof (``step_up={provider, at}``, honored ≤ TTL).
    """
    internal = datasette.get_internal_database()
    ip = security.client_ip(datasette, request)
    actor_id = (state or {}).get("a")
    target = ((state or {}).get("u") or {}).get("target")
    # The identity must belong to the acting account (proof of control of an
    # existing method), and the state must name a target to link into.
    if existing is None or existing["user_id"] != actor_id or not target:
        await db.record_login_attempt(
            internal, None, ip, False, "provider_state_invalid", provider=provider_key
        )
        return _refuse(response_mode)
    # Redirect into the target provider's start, minting the link-intent state.
    response = Response.redirect(datasette.setting("base_url") or "/")
    value = make_state(
        datasette,
        request,
        response,
        provider=target,
        next="/-/account",
        intent="link",
        actor_id=actor_id,
        step_up={"provider": provider_key, "at": db.now_iso()},
    )
    start = datasette.urls.path(f"/-/login/provider/{target}/start")
    # Response.redirect wrote the "Location" header (capital L); overwrite that
    # exact key so we don't emit a second, lowercase location header.
    response.headers["Location"] = f"{start}?state={quote(value)}"
    return response


async def _finish_link(
    datasette, request, identity, existing, *, provider_key, response_mode, state
):
    """Complete a link: attach ``identity`` to the state's bound actor, provided
    that actor still matches the LIVE session (a stolen/forged state built for
    user A cannot be redeemed under user B's session) and — for password-less
    origins — the step-up proof is within TTL. An identity already linked to
    ANYONE (including this account) yields a generic "already in use" page: a
    link callback must never mint, so completing it with a victim's identity can
    never sign the attacker in as the victim.
    """
    internal = datasette.get_internal_database()
    ip = security.client_ip(datasette, request)

    if existing is not None:
        # Already claimed (by this account or another) — generic, no disclosure,
        # no session. This is the branch that defeats "link a victim's identity
        # to get signed in as them": we return a 409 page, never a mint.
        return _error_page(
            response_mode, "That identity is already in use.", status=409
        )

    actor_id = (state or {}).get("a")
    # The state's bound actor must equal the live session's actor. resolve_actor
    # rebuilds identity straight from the session cookie (lazy import: __init__
    # imports this module before resolve_actor is defined).
    from .. import resolve_actor

    live = await resolve_actor(datasette, request)
    if not actor_id or live is None or live["id"] != actor_id:
        await db.record_login_attempt(
            internal, None, ip, False, "provider_state_invalid", provider=provider_key
        )
        return _refuse(response_mode)

    # Password-less origin: the link state carries a step-up proof, honored only
    # within provider_state_ttl_minutes of the step-up completion.
    step_up = (state or {}).get("u") or {}
    if step_up.get("at") is not None or step_up.get("provider") is not None:
        ttl = security.config(datasette, "provider_state_ttl_minutes")
        cutoff = (
            datetime.now(timezone.utc) - timedelta(minutes=ttl)
        ).isoformat(timespec="milliseconds")
        at = step_up.get("at")
        if not at or at <= cutoff:
            await db.record_login_attempt(
                internal, None, ip, False, "provider_state_invalid",
                provider=provider_key,
            )
            return _refuse(response_mode)

    try:
        await db.link_identity(internal, actor_id, actor_id, identity)
    except db.AlreadyLinkedError:
        # Lost the race to another writer (PK backstop) — same generic outcome.
        return _error_page(
            response_mode, "That identity is already in use.", status=409
        )

    response = Response.redirect(datasette.urls.path("/-/account"))
    clear_state_cookie(response)
    return response


async def _provision_pending(datasette, request, identity, *, provider_key, response_mode):
    """Approval-mode provisioning: shared abuse caps, then create a pending
    account (no session). Caps + the `register` login_audit reason are shared
    with password self-registration so the per-IP/day + pending-queue budgets
    are unified across every provider (design D5)."""
    internal = datasette.get_internal_database()
    ip = security.client_ip(datasette, request)
    over_cap = await _registration_over_cap(datasette, internal, ip)
    audit_name = identity.username_hint or identity.subject
    if over_cap:
        # Refused attempts still count toward the per-IP budget (reason
        # 'register'), exactly as a capped password signup does.
        await db.record_login_attempt(
            internal, audit_name, ip, False, "register", provider=provider_key
        )
        return _refuse_closed(response_mode)
    await db.provision_external_user(internal, identity, ip, pending=True)
    # Same 'register' reason as a password signup → one shared per-IP counter.
    await db.record_login_attempt(
        internal, audit_name, ip, True, "register", provider=provider_key
    )
    return _pending(response_mode)


async def _registration_over_cap(datasette, internal, ip):
    """True when either self-registration abuse cap is at/over limit. Shared,
    verbatim, with the password register path (providers/password.register)."""
    per_ip_cap = security.config(datasette, "registrations_per_ip_per_day")
    queue_cap = security.config(datasette, "max_pending_registrations")
    return (
        await db.count_recent_registrations(internal, ip) >= per_ip_cap
        or await db.count_pending_users(internal) >= queue_cap
    )


async def _mint_external(datasette, request, user, *, provider_key, response_mode, state):
    """Mint for a linked/auto-provisioned external account, writing the success
    login_audit row here (with the provider column) — external flows have no
    verify half to write it, unlike password."""
    internal = datasette.get_internal_database()
    ip = security.client_ip(datasette, request)
    await db.record_login_attempt(
        internal, user["username"], ip, True, "success", provider=provider_key
    )
    return await _mint_and_respond(
        datasette,
        request,
        user,
        provider_key=provider_key,
        response_mode=response_mode,
        state=state,
    )


async def _mint_and_respond(datasette, request, user, *, provider_key, response_mode, state):
    """Shared success tail for every finish_login path: build the response,
    mint the session (provenance = provider_key), run the periodic housekeeping,
    clear the state cookie. Does NOT write the success login_audit row — that is
    the caller's responsibility (password's verify half; _mint_external for
    external flows) so the row is written exactly once."""
    internal = datasette.get_internal_database()
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

    await mint_session(datasette, request, response, user, provider=provider_key)
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
    return _error_page(response_mode, GENERIC_FLOW_ERROR, status=403)


def _refuse_no_account(response_mode):
    # Deliberately identical whether signups are off or the identity is simply
    # unknown — never distinguishes the two (design §4).
    return _error_page(response_mode, "No account is linked to that identity.", status=403)


def _refuse_closed(response_mode):
    # Mirrors the password register over-cap message; never says which cap tripped.
    return _error_page(
        response_mode, "Registration is currently closed — try again later.", status=429
    )


def _pending(response_mode):
    """The 'awaiting approval' outcome — no session. Mirrors the register page:
    JSON callers get {"ok": True}; redirect flows get a plain confirmation page."""
    if response_mode == "json":
        response = Response.json({"ok": True})
    else:
        response = Response.html(
            "<h1>Account created</h1>"
            "<p>Your account is awaiting approval by an administrator.</p>"
        )
    clear_state_cookie(response)
    return response


def _error_page(response_mode, message, *, status):
    if response_mode == "json":
        response = Response.json({"ok": False, "error": message}, status=status)
    else:
        response = Response.html(
            f"<h1>Sign-in failed</h1><p>{message}</p>", status=status
        )
    clear_state_cookie(response)
    return response
