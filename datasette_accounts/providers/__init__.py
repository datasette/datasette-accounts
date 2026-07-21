"""Pluggable sign-in providers: the contract, signed state, and finish_login.

Providers authenticate; datasette-accounts owns identity, policy, and sessions
(plans/auth-providers/02-design.md §§1–4). A provider registers its own routes
under ``/-/{plugin}/...`` (the ordinary Datasette ``register_routes`` hook, the
datasette-paper model) and ends every flow by returning ``await finish_login(...)``
— the single termination point that runs the account gates and mints the session.
Core owns the signed OAuth ``state`` (``make_state`` / ``read_state``) so no
provider hand-rolls it, and offers the optional ``provider_gate`` decorator that
gives any provider route the enabled-404 + CSRF-on-POST + method-gate behaviour in
one line.

Core-01 scope (plans/auth2/tickets/core-01-contract.md): the full contract with
**no external login path**. ``finish_login`` fully implements the ``LocalIdentity``
termination (password / invite / reset completion); the ``ExternalIdentity``
dataclass shape is declared now so the ``finish_login`` signature and the provider
public surface stay stable, but the external mapping / provisioning / linking /
enabled re-check land in core-03.
"""

from __future__ import annotations

import re
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from functools import wraps
from typing import TYPE_CHECKING, Any, TypedDict

from datasette import Response

from .. import db, security
from ..security import COOKIE_NAME, SIGN_NAMESPACE
from ..sessions import mint_token, token_sha256

if TYPE_CHECKING:
    # Type-only imports: importing Datasette/Request at module load would pull
    # the full app in before this plugin's submodules finish importing.
    # ``from __future__ import annotations`` makes every annotation a string, so
    # these names are never evaluated at runtime.
    from collections.abc import Awaitable, Callable

    from datasette.app import Datasette
    from datasette.utils.asgi import Request

    # A provider-owned route handler as Datasette's register_routes calls it:
    # keyword-injected ``datasette`` + ``request`` (any URL captures ride in
    # ``request.url_vars``), returning a Response.
    RouteHandler = Callable[[Datasette, Request], Awaitable[Response]]

# Provider keys: lowercase slug, must start with an alphanumeric. "password" is
# reserved for the built-in provider; it matches KEY_RE like any other key, so
# the registry validates it the same way and simply rejects a *duplicate*.
KEY_RE = re.compile(r"^[a-z0-9][a-z0-9-]*$")

# Optional descriptor branding (see AuthProvider.icon / .brand_color):
# brand_color must be a plain hex CSS colour.
BRAND_COLOR_RE = re.compile(r"^#(?:[0-9a-fA-F]{3}|[0-9a-fA-F]{6})$")

# Signed-state cookie + namespace, and the attribute the registry lives on.
STATE_COOKIE = "ds_accounts_state"
STATE_NAMESPACE = "datasette-accounts-state"
REGISTRY_ATTR = "_datasette_accounts_providers"

# Shown to the visitor when finish_login refuses. Deliberately generic: it must
# never distinguish "disabled" from "expired" from "pending" (the specific
# reason lives only in the admin-only login_audit).
GENERIC_FLOW_ERROR = "Unable to sign in"


class AuthProvider:
    """Descriptor for a sign-in provider (see design §2/§3).

    A provider is a small descriptor plus its own routes — it does **not**
    implement a dispatch method. Subclasses set three attributes:

    ``key``
        KEY_RE slug; unique; "password" is reserved for the built-in provider.
    ``label``
        Human name, e.g. "GitHub", rendered as "Continue with {label}".
    ``start_path``
        Absolute path (leading "/") to the provider's own *start* route, e.g.
        ``"/-/discord-auth/start"``; the built-in password provider's is
        ``"/-/login"``. The login-page button and the link/step-up forwards
        point the visitor here (threading a validated ``?next=`` / ``?state=``).
        Startup validates it is non-empty and starts with "/".

    Two optional presentation attributes brand the login button (a declarative
    amendment to D10 — descriptors carry data, still no provider-owned HTML
    surface):

    ``icon``
        A single inline ``<svg>…</svg>`` element, rendered inside the button
        before "Continue with {label}". Use ``fill="currentColor"`` so it
        inherits the button's text colour. Startup validates the shape (must be
        one ``<svg>`` element, no ``<script``) — a lint for trusted plugin
        authors, not a security boundary: a provider is installed Python and
        could already do anything.
    ``brand_color``
        Hex CSS colour (``#5865F2``) used as the button's background with white
        text; omit for the neutral default button. Startup validates the hex
        shape (ICON/BRAND checks live in ``__init__.startup``).

    Providers own their URL surface via the ordinary Datasette
    ``register_routes`` hook and terminate every flow by returning
    ``await finish_login(...)``. Wrapping each route handler in
    ``@provider_gate(key)`` is recommended (enabled-404 + CSRF-on-POST + method
    gate), but is not load-bearing for security: ``finish_login`` re-checks the
    enabled bit (for external identities, core-03) and refuses a disabled
    provider even for an ungated route.
    """

    key: str
    label: str
    start_path: str
    icon: str | None = None
    brand_color: str | None = None

    def configured(self, datasette: Datasette) -> bool | Awaitable[bool]:
        """Is this provider ready to authenticate (credentials/config present)?
        Checked before offering the provider to users (login button, link
        targets). Distinct from the admin enabled bit: enabled is runtime
        policy, configured is deployment state. Default True.

        Usually a plain sync method (a fixed set of env vars, checked instantly).
        May instead return an *awaitable* bool for a provider whose readiness
        depends on a runtime, DB-backed value that can only be read
        asynchronously (e.g. an email-based provider awaiting a sender setting):

        ```python
        async def configured(self, datasette: Datasette) -> bool:
            return await some_async_readiness_check(datasette)
        ```

        Both forms are supported by every call site (``provider_configured``
        awaits the result only when it is itself awaitable), so an existing sync
        override needs no change.
        """
        return True


async def provider_configured(datasette: Datasette, provider: AuthProvider) -> bool:
    """Defensively evaluate ``provider.configured(datasette)`` — sync or async.

    ``configured`` may return a plain ``bool`` or an *awaitable* one (see its
    docstring); this is the one call site every caller goes through, so it is
    the only place that needs to know about both shapes. A provider that raises
    (or whose awaited result raises) counts as NOT configured — a provider that
    can't answer whether it is deployable must not be offered to users. The
    registry-building code (``__init__.startup``) fails loud on a misbehaving
    provider descriptor, but that is startup; this runs on every user-facing
    request, so it swallows rather than 500s. There is no logging surface in
    this module, so the swallow is silent (matching read_state's and
    resolve_actor's broad guards around untrusted/provider code)."""
    try:
        result = provider.configured(datasette)
        if callable(getattr(result, "__await__", None)):
            result = await result
        return bool(result)
    except Exception:
        return False


def validate_branding(provider: AuthProvider) -> None:
    """Startup lint for the optional icon/brand_color descriptor attributes.

    Raises RuntimeError (startup fails loudly, like the key/start_path checks).
    The icon lands in the login page via ``{@html}``, so require it to be one
    inline ``<svg>…</svg>`` element with no ``<script`` — this catches an author
    pasting a data URL, a whole HTML snippet, or an ``<img>`` tag; it is NOT a
    sanitizer (an installed provider is trusted Python already)."""
    icon = getattr(provider, "icon", None)
    if icon is not None:
        trimmed = icon.strip() if isinstance(icon, str) else ""
        if (
            not trimmed.startswith("<svg")
            or not trimmed.endswith("</svg>")
            or "<script" in trimmed.lower()
        ):
            raise RuntimeError(
                f"Auth provider {provider.key!r} has an invalid icon: must be "
                "a single inline <svg>…</svg> element"
            )
    brand_color = getattr(provider, "brand_color", None)
    if brand_color is not None and not (
        isinstance(brand_color, str) and BRAND_COLOR_RE.match(brand_color)
    ):
        raise RuntimeError(
            f"Auth provider {provider.key!r} has an invalid brand_color: "
            f"{brand_color!r} (expected a hex colour like '#5865F2')"
        )


def provider_gate(key: str) -> Callable[[RouteHandler], RouteHandler]:
    """Decorator for a provider-owned route handler (optional but recommended).

    Reproduces, per route, exactly what the old core mount did in front of every
    provider request (design §3):

    * **404** when the provider is disabled: the gated URL surface goes dead.
      (Honest caveat: this plain-text 404 differs from Datasette's HTML 404 for
      never-registered paths, so "installed but disabled" is distinguishable
      from "not installed" — the D3b trade-off, accepted as low-sensitivity;
      see plans/auth-providers/03-decisions.md D3b.)
    * **CSRF gate** on POST (``security.csrf_error`` → plain-text 403, matching
      the old core mount): form / OAuth providers that POST get the core
      CSRF check for free.
    * **405** on any method other than GET / HEAD / POST.

    Skipping this decorator cannot yield a session: ``finish_login`` re-checks
    the enabled bit before any external mint / provision / link (core-03), so an
    ungated route on a disabled provider still authenticates nobody. The gate is
    defence in depth and surface hygiene, not the load-bearing control.
    """

    def decorator(handler: RouteHandler) -> RouteHandler:
        @wraps(handler)
        async def wrapper(datasette: Datasette, request: Request) -> Response:
            internal = datasette.get_internal_database()
            if not await db.get_provider_enabled(internal, key):
                return Response.text("Not found", status=404)
            if request.method == "POST":
                problem = security.csrf_error(request)
                if problem:
                    return Response.text(problem, status=403)
            elif request.method not in ("GET", "HEAD"):
                return Response.text("Method not allowed", status=405)
            return await handler(datasette, request)

        return wrapper

    return decorator


@dataclass(frozen=True)
class LocalIdentity:
    user_id: str  # an existing datasette_accounts_users.id


@dataclass(frozen=True)
class ExternalIdentity:
    """A proven external identity (declared now for signature stability).

    The external login path — mapping ``(provider, subject)`` through the
    identities table, provisioning, linking, and the provider enabled re-check —
    arrives in core-03. Core-01 declares the shape so ``finish_login``'s
    signature and the provider public surface never move underneath plugins.
    """

    provider: str  # must equal the calling provider's key
    subject: str  # the IdP's *stable* user id — never an email
    email: str | None = None
    email_verified: bool = False
    username_hint: str | None = None  # e.g. the gh login — provisioning only
    display_name: str | None = None  # audit detail only; we store no profile


# What a provider hands finish_login: an existing local account (password /
# invite / reset completion) or a proven external identity (core-03).
Identity = LocalIdentity | ExternalIdentity


# The built-in username/password provider lives in providers/password.py so the
# login/register/set-password code it owns can move there (core-02) without a
# circular import against this module's finish_login.


# --------------------------------------------------------------------------
# Signed state — core-owned, provider-consumed (design §2)
# --------------------------------------------------------------------------


class State(TypedDict):
    """The signed OAuth-``state`` payload minted by ``make_state`` and returned
    by ``read_state``. Keys are single letters to keep the signed cookie small;
    ``make_state`` always writes all of them, so the shape is total.

    ``u`` (step-up proof / link target) is a small heterogeneous dict carried
    for the link / step-up flows (core-03/04), hence ``dict[str, str] | None``.
    """

    s: str  # random nonce, double-submitted as the `state` query arg
    p: str  # provider key this state is bound to
    n: str  # validated post-login `next` path (validate_next never returns None)
    i: str  # intent: "login" | "link" | "step-up"
    a: str | None  # bound actor id (link / step-up flows), else None
    u: dict[str, str] | None  # step-up proof / link target, else None
    c: str  # created-at ISO8601 (millisecond + offset), for the TTL check


def make_state(
    datasette: Datasette,
    request: Request,
    response: Response,
    *,
    provider: str,
    next: str | None = None,
    intent: str = "login",
    actor_id: str | None = None,
    step_up: dict[str, str] | None = None,
) -> str:
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


def read_state(
    datasette: Datasette, request: Request, *, provider: str
) -> State | None:
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


def clear_state_cookie(response: Response) -> None:
    response.set_cookie(STATE_COOKIE, "", max_age=0, path="/", expires=0)


# --------------------------------------------------------------------------
# Registry access
# --------------------------------------------------------------------------


def get_registry(datasette: Datasette) -> dict[str, AuthProvider]:
    """The provider registry dict {key: AuthProvider} built at startup (§3)."""
    return getattr(datasette, REGISTRY_ATTR, {})


# --------------------------------------------------------------------------
# Session cookie (own copies, so no existing route changes — core-02
# consolidates these with routes/api.py's identical helpers)
# --------------------------------------------------------------------------


def set_session_cookie(
    datasette: Datasette, request: Request, response: Response, raw_token: str
) -> None:
    response.set_cookie(
        COOKIE_NAME,
        datasette.sign(raw_token, SIGN_NAMESPACE),
        max_age=security.config(datasette, "session_ttl_days") * 86400,
        path="/",
        httponly=True,
        samesite="lax",
        secure=security.should_secure_cookie(datasette, request),
    )


def clear_stale_core_actor_cookie(request: Request, response: Response) -> None:
    # This plugin owns auth via its own session cookie, but a leftover core
    # `ds_actor` cookie (e.g. an old root login) makes Datasette's base
    # template render its own Log out button next to ours. Signing in through
    # our flows asserts accounts-based identity, so drop the stale core cookie
    # whenever it is present.
    if "ds_actor" in request.cookies:
        response.set_cookie("ds_actor", "", max_age=0, path="/", expires=0)


async def mint_session(
    datasette: Datasette,
    request: Request,
    response: Response,
    user: dict[str, Any],
) -> None:
    """The single session mint: stamp login success, create the session row,
    and set the session + stale-core cookies on ``response``.

    This is exactly authenticate()'s historical success half minus the periodic
    housekeeping, so callers that want housekeeping (finish_login) run it around
    this. The one ``db.create_session`` call finish_login reaches lives here.
    (Session-provenance stamping — the ``provider`` column — lands with the
    core-03 migration alongside the external identities table.)
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
    datasette: Datasette,
    request: Request,
    identity: Identity,
    *,
    provider_key: str,
    response_mode: str = "redirect",
    state: State | None = None,
) -> Response:
    """Terminate a sign-in flow: run account gates, then mint.

    `provider_key` is the key of the provider that produced `identity` (it will
    become the session + login_audit provenance in core-03). `LocalIdentity`
    (password / invite / reset completion) loads the user directly and is fully
    implemented here. `ExternalIdentity` — the ``(provider, subject)`` mapping,
    the provider enabled re-check, and the per-provider signups policy — arrives
    in core-03; core-01 declares the shape but raises for it.
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
        # Declared for signature stability; the external login path (mapping,
        # provisioning, linking, enabled re-check) lands in core-03.
        raise NotImplementedError(
            "External-identity sign-in is implemented in core-03 (identities)"
        )
    raise TypeError(f"Unknown identity type: {type(identity)!r}")


def _gate_reason(user: dict[str, Any] | None) -> str | None:
    """Account gate for a local identity — disabled > expired > pending
    precedence, matching authenticate()'s gates. Returns a login_audit reason
    string, or None when the account may sign in."""
    if user is None:
        return "no_such_user"
    if user["disabled"]:
        return "disabled"
    if user["expires_at"] and user["expires_at"] <= db.now_iso():
        return "expired"
    if user["pending_approval"]:
        return "pending_approval"
    return None


async def _finish_local(datasette, request, identity, *, response_mode, state):
    internal = datasette.get_internal_database()
    ip = security.client_ip(datasette, request)
    user = await db.get_user_by_id(internal, identity.user_id)

    # Same gates, same precedence as authenticate(): disabled > expired >
    # pending_approval. (For the password provider the verify half already ran
    # in the caller and writes the success row; this is the shared,
    # defense-in-depth chokepoint, so we write only refusals here.)
    reason = _gate_reason(user)
    if reason is not None:
        await db.record_login_attempt(
            internal, user["username"] if user else None, ip, False, reason
        )
        return _refuse(response_mode)

    return await _mint_and_respond(
        datasette, request, user, response_mode=response_mode, state=state
    )


async def _mint_and_respond(datasette, request, user, *, response_mode, state):
    """Shared success tail: build the response, mint the session, run the
    periodic housekeeping, clear the state cookie. Does NOT write the success
    login_audit row — that is the caller's responsibility (password's verify
    half) so the row is written exactly once."""
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
    return _error_page(response_mode, GENERIC_FLOW_ERROR, status=403)


def _error_page(response_mode, message, *, status):
    if response_mode == "json":
        response = Response.json({"ok": False, "error": message}, status=status)
    else:
        response = Response.html(
            f"<h1>Sign-in failed</h1><p>{message}</p>", status=status
        )
    clear_state_cookie(response)
    return response
