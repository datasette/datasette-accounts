"""HTML page shells.

Each page renders the single base template with a Vite `entrypoint` and
`page_data`; the Svelte app mounts on `#app-root` and reads `#pageData`. The
logout page is a tiny dependency-free redirect (no Svelte needed).
"""

from datasette import NotFound, Response

from .. import db, grantable, messages, security
from ..page_data import (
    AccountPageData,
    AdminAuditPageData,
    AdminPageData,
    CapabilitiesPageData,
    ConfigPageData,
    LoginAttemptRow,
    LoginAttemptsPageData,
    LoginPageData,
    RegisterPageData,
    SetPasswordPageData,
    UserRow,
)
from ..router import require_admin_page, router
from ..sessions import list_own_sessions, token_sha256
from .api import audit_entries


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
    page_data = LoginPageData(
        next=next_value,
        help=help_text,
        allow_register=await db.get_registration_enabled(internal),
        password_enabled=await db.get_provider_enabled(internal, "password"),
    ).model_dump()
    return await _render(
        datasette, request, "src/pages/login/index.ts", "Log in", page_data
    )


@router.GET("/-/register$")
async def register_page(datasette, request):
    # 404 (not e.g. a signed-out redirect) while signups are closed — the
    # page's existence isn't advertised any differently than a route that
    # was never registered. Re-checked on submit too, since the toggle can
    # flip between page load and submit. A disabled password provider also
    # closes signups (design §8), regardless of the registration toggle.
    internal = datasette.get_internal_database()
    if not await db.get_provider_enabled(
        internal, "password"
    ) or not await db.get_registration_enabled(internal):
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
    # the sessions read entirely rather than assembling data nobody sees.
    sessions = []
    if not must_change_password:
        internal = datasette.get_internal_database()
        sessions = await list_own_sessions(datasette, request, internal, actor["id"])
    page_data = AccountPageData(
        id=actor["id"],
        username=actor.get("username", ""),
        is_admin=bool(actor.get("is_admin")),
        must_change_password=must_change_password,
        sessions=sessions,
    ).model_dump()
    return await _render(
        datasette, request, "src/pages/account/index.ts", "Your account", page_data
    )


@router.GET("/-/admin/users$")
@require_admin_page
async def admin_page(datasette, request):
    internal = datasette.get_internal_database()
    rows = await db.list_user_rows(internal)
    users = [UserRow(**r) for r in rows]
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
    page_data = ConfigPageData(
        **view,
        registration_enabled=await db.get_registration_enabled(internal),
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
