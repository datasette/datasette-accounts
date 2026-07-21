"""HTML page shells.

Each page renders the single base template with a Vite `entrypoint` and
`page_data`; the Svelte app mounts on `#app-root` and reads `#pageData`. The
logout page is a tiny dependency-free redirect (no Svelte needed).
"""

from urllib.parse import quote

from datasette import NotFound, Response

from .. import db, grantable, messages, security
from ..page_data import (
    AccountPageData,
    AdminAuditPageData,
    AdminPageData,
    CapabilitiesPageData,
    ConfigPageData,
    LinkableProvider,
    LoginAttemptRow,
    LoginAttemptsPageData,
    LoginPageData,
    ProviderAdminRow,
    ProviderButton,
    RegisterPageData,
    SetPasswordPageData,
)
from ..passwords import UNUSABLE_PASSWORD
from ..providers import (
    external_provider_keys,
    get_registry,
    provider_configured,
    provider_label,
    provider_source,
    provider_start_path,
    to_identity_rows,
)
from ..router import require_admin_page, router
from ..sessions import list_own_sessions, token_sha256
from .api import _user_row, audit_entries


async def _render(datasette, request, entrypoint, page_title, page_data):
    return Response.html(
        await datasette.render_template(
            "accounts_base.html",
            {
                "page_title": page_title,
                "entrypoint": entrypoint,
                "page_data": page_data,
            },
            request=request,
        )
    )


@router.GET("/-/login$")
async def login_page(datasette, request):
    next_value = security.validate_next(
        request.args.get("next"), datasette.setting("base_url") or "/"
    )
    internal = datasette.get_internal_database()
    help_text = await db.get_site_message(internal, "login_help") or ""
    # One "Continue with …" button per ENABLED external provider (registry
    # order). The validated `next` rides along as a query arg; the provider's own
    # start route folds it into the signed state so the post-login redirect
    # honours it. The whole surface is redirect-based (full-page navigation, not
    # fetch). `start_url` comes from each descriptor's own `start_path` (D3b).
    registry = get_registry(datasette)
    providers = []
    for key in external_provider_keys(datasette):
        # Enabled AND configured: a provider whose credentials aren't deployed
        # (e.g. a sample without its env vars) is enabled-but-not-ready — its
        # start route 503s — so we don't offer a button that dead-ends.
        if await db.get_provider_enabled(internal, key) and await provider_configured(
            datasette, registry[key]
        ):
            start = provider_start_path(datasette, key)
            providers.append(
                ProviderButton(
                    key=key,
                    label=registry[key].label,
                    start_url=f"{start}?next={quote(next_value)}",
                    icon=registry[key].icon,
                    brand_color=registry[key].brand_color,
                )
            )
    page_data = LoginPageData(
        next=next_value,
        help=help_text,
        allow_register=await db.get_registration_enabled(internal),
        password_enabled=await db.get_provider_enabled(internal, "password"),
        providers=providers,
    ).model_dump()
    return await _render(
        datasette, request, "src/pages/login/index.ts", "Log in", page_data
    )


@router.GET("/-/register$")
async def register_page(datasette, request):
    # 404 (not e.g. a signed-out redirect) while signups are closed — the
    # page's existence isn't advertised any differently than a route that
    # was never registered. Re-checked on submit too, since the toggle can
    # flip between page load and submit.
    internal = datasette.get_internal_database()
    if not await db.get_registration_enabled(internal):
        raise NotFound("Not found")
    if request.actor:
        return Response.redirect(datasette.urls.path("/"))
    help_text = await db.get_site_message(internal, "register_help") or ""
    page_data = RegisterPageData(help=help_text).model_dump()
    return await _render(
        datasette, request, "src/pages/register/index.ts", "Register", page_data
    )


@router.GET("/-/set-password$")
async def set_password_page(datasette, request):
    # Anonymous: an invite/reset link proves control of the account, not a
    # signed-in session. Never say *why* a token is invalid (missing, expired,
    # already used, or unknown) — one generic state for all of them, and a
    # login_audit row so admins can see probing.
    token = request.args.get("token") or ""
    internal = datasette.get_internal_database()
    row = await db.get_password_token(internal, token_sha256(token)) if token else None
    if row:
        page_data = SetPasswordPageData(
            valid=True,
            purpose=row["purpose"],
            username=row["username"],
            token=token,
        ).model_dump()
    else:
        ip = security.client_ip(datasette, request)
        await db.record_login_attempt(internal, None, ip, False, "bad_token")
        page_data = SetPasswordPageData(valid=False).model_dump()
    return await _render(
        datasette,
        request,
        "src/pages/set-password/index.ts",
        "Set your password",
        page_data,
    )


@router.GET("/-/logout$")
async def logout_page(datasette, request):
    # A GET page whose fetch() POSTs the logout (JSON, so the CSRF gate passes).
    # A bare GET must never destroy the session.
    return Response.html(
        """<!doctype html><meta charset="utf-8"><title>Log out</title>
<h1>Logging out…</h1>
<noscript><p>JavaScript is required to log out.</p></noscript>
<script>
fetch('/-/logout/perform', {method: 'POST', headers: {'Content-Type': 'application/json'}, body: '{}'})
  .then(() => { location = '/'; });
</script>"""
    )


@router.GET("/-/account$")
async def account_page(datasette, request):
    if not request.actor:
        return Response.redirect(datasette.urls.path("/-/login?next=/-/account"))
    actor = request.actor
    must_change_password = bool(actor.get("must_change_password"))
    # During the forced-change state the page renders password-only, so skip
    # the sessions + sign-in-methods reads entirely rather than assembling data
    # nobody sees.
    sessions = []
    identities = []
    linkable = []
    has_password = True
    if not must_change_password:
        internal = datasette.get_internal_database()
        sessions = await list_own_sessions(datasette, request, internal, actor["id"])
        user = await db.get_user_by_id(internal, actor["id"])
        has_password = bool(user) and user["password_hash"] != UNUSABLE_PASSWORD
        raw_identities = await db.list_identities(internal, actor["id"])
        identities = to_identity_rows(datasette, raw_identities)
        linked_keys = {i["provider"] for i in raw_identities}
        # Linkable = installed external providers, enabled, configured, not
        # already linked. Carry the label so the "Link…" button can name the
        # provider directly. An unconfigured provider (no credentials deployed)
        # can't complete a link flow, so it's filtered out exactly like the
        # login button.
        registry = get_registry(datasette)
        for key in external_provider_keys(datasette):
            if (
                key not in linked_keys
                and await db.get_provider_enabled(internal, key)
                and await provider_configured(datasette, registry[key])
            ):
                linkable.append(
                    LinkableProvider(key=key, label=provider_label(datasette, key))
                )
    page_data = AccountPageData(
        id=actor["id"],
        username=actor.get("username", ""),
        is_admin=bool(actor.get("is_admin")),
        must_change_password=must_change_password,
        sessions=sessions,
        identities=identities,
        linkable_providers=linkable,
        has_password=has_password,
    ).model_dump()
    return await _render(
        datasette, request, "src/pages/account/index.ts", "Your account", page_data
    )


@router.GET("/-/admin/users$")
@require_admin_page
async def admin_page(datasette, request):
    internal = datasette.get_internal_database()
    rows = await db.list_user_rows(internal)
    users = [_user_row(datasette, r) for r in rows]
    page_data = AdminPageData(users=users, viewer_id=request.actor["id"]).model_dump()
    return await _render(
        datasette, request, "src/pages/admin/index.ts", "Accounts", page_data
    )


@router.GET("/-/admin/capabilities$")
@require_admin_page
async def capabilities_page(datasette, request):
    internal = datasette.get_internal_database()
    view = await grantable.grantable_view(datasette, internal)
    page_data = CapabilitiesPageData(**view).model_dump()
    return await _render(
        datasette,
        request,
        "src/pages/capabilities/index.ts",
        "Capabilities",
        page_data,
    )


@router.GET("/-/admin/config$")
@require_admin_page
async def config_page(datasette, request):
    internal = datasette.get_internal_database()
    view = await messages.slots_view(internal)
    counts = await db.count_identities_by_provider(internal)
    providers = [
        ProviderAdminRow(
            key=key,
            label=provider.label,
            source=provider_source(provider),
            builtin=key == "password",
            enabled=await db.get_provider_enabled(internal, key),
            configured=await provider_configured(datasette, provider),
            signups=await db.get_provider_signups(internal, key),
            linked_count=counts.get(key, 0),
        )
        for key, provider in get_registry(datasette).items()
    ]
    page_data = ConfigPageData(
        **view,
        registration_enabled=await db.get_registration_enabled(internal),
        providers=providers,
    ).model_dump()
    return await _render(
        datasette, request, "src/pages/config/index.ts", "Configuration", page_data
    )


@router.GET("/-/admin/login-attempts$")
@require_admin_page
async def login_attempts_page(datasette, request):
    internal = datasette.get_internal_database()
    # The Accounts row menu links here with ?username=…; ?ip=… is also honoured.
    username = request.args.get("username") or ""
    ip = request.args.get("ip") or ""
    rows = await db.list_login_attempts(internal, username or None, ip or None)
    attempts = [
        LoginAttemptRow(**{k: r.get(k) for k in LoginAttemptRow.model_fields})
        for r in rows
    ]
    page_data = LoginAttemptsPageData(
        attempts=attempts, filter_username=username, filter_ip=ip
    ).model_dump()
    return await _render(
        datasette,
        request,
        "src/pages/login-attempts/index.ts",
        "Login attempts",
        page_data,
    )


@router.GET("/-/admin/audit$")
@require_admin_page
async def admin_audit_page(datasette, request):
    internal = datasette.get_internal_database()
    # The Accounts row menu links here with ?username=…; ?operation= is also
    # honoured.
    username = request.args.get("username") or ""
    operation = request.args.get("operation") or ""
    entries = await audit_entries(internal, username, operation)
    operations = await db.list_admin_audit_operations(internal)
    page_data = AdminAuditPageData(
        entries=entries,
        operations=operations,
        filter_username=username,
        filter_operation=operation,
    ).model_dump()
    return await _render(
        datasette,
        request,
        "src/pages/audit/index.ts",
        "Admin history",
        page_data,
    )
