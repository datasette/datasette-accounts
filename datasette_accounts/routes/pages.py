"""HTML page shells.

Each page renders the single base template with a Vite `entrypoint` and
`page_data`; the Svelte app mounts on `#app-root` and reads `#pageData`. The
logout page is a tiny dependency-free redirect (no Svelte needed).
"""

from datasette import Response

from .. import db, grantable, messages, security
from ..page_data import (
    AccountPageData,
    AdminPageData,
    CapabilitiesPageData,
    LoginAttemptRow,
    LoginAttemptsPageData,
    LoginPageData,
    MessagesPageData,
    UserRow,
)
from ..router import require_admin_page, router


async def _render(datasette, entrypoint, page_title, page_data):
    return Response.html(
        await datasette.render_template(
            "accounts_base.html",
            {
                "page_title": page_title,
                "entrypoint": entrypoint,
                "page_data": page_data,
            },
        )
    )


@router.GET("/-/login$")
async def login_page(datasette, request):
    next_value = security.validate_next(
        request.args.get("next"), datasette.setting("base_url") or "/"
    )
    internal = datasette.get_internal_database()
    help_text = await db.get_site_message(internal, "login_help") or ""
    page_data = LoginPageData(next=next_value, help=help_text).model_dump()
    return await _render(datasette, "src/pages/login/index.ts", "Log in", page_data)


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
    page_data = AccountPageData(
        id=actor["id"],
        username=actor.get("username", ""),
        is_admin=bool(actor.get("is_admin")),
        must_change_password=bool(actor.get("must_change_password")),
    ).model_dump()
    return await _render(
        datasette, "src/pages/account/index.ts", "Your account", page_data
    )


@router.GET("/-/admin/users$")
@require_admin_page
async def admin_page(datasette, request):
    internal = datasette.get_internal_database()
    rows = await db.list_users(internal)
    users = [UserRow(**db.to_user_row(r)) for r in rows]
    page_data = AdminPageData(users=users).model_dump()
    return await _render(datasette, "src/pages/admin/index.ts", "Accounts", page_data)


@router.GET("/-/admin/capabilities$")
@require_admin_page
async def capabilities_page(datasette, request):
    internal = datasette.get_internal_database()
    view = await grantable.grantable_view(datasette, internal)
    page_data = CapabilitiesPageData(**view).model_dump()
    return await _render(
        datasette, "src/pages/capabilities/index.ts", "Capabilities", page_data
    )


@router.GET("/-/admin/messages$")
@require_admin_page
async def messages_page(datasette, request):
    internal = datasette.get_internal_database()
    view = await messages.slots_view(internal)
    page_data = MessagesPageData(**view).model_dump()
    return await _render(
        datasette, "src/pages/messages/index.ts", "Messages", page_data
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
        "src/pages/login-attempts/index.ts",
        "Login attempts",
        page_data,
    )
