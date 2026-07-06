import json
import os

import click
from datasette import hookimpl
from datasette.permissions import Action, PermissionSQL
from datasette_vite import vite_entry
from sqlite_utils import Database as SqliteUtilsDatabase

from . import db, security
from .internal_migrations import internal_migrations
from .passwords import hash_password
from .router import ADMIN_ACTION, router
from .security import COOKIE_NAME, SIGN_NAMESPACE
from .sessions import token_sha256

# Import route modules to register their handlers on the shared router.
from .routes import api, pages  # noqa: E402

# Re-exported so pluggy discovers the hookimpl on this plugin module (M6).
from .seeds import datasette_user_profile_seeds  # noqa: E402,F401

_ = (api, pages)


@hookimpl
def register_routes():
    return router.routes()


@hookimpl
def extra_template_vars(datasette):
    entry = vite_entry(
        datasette=datasette,
        plugin_package="datasette_auth_basic_login",
    )
    return {"datasette_auth_basic_login_vite_entry": entry}


@hookimpl
def register_actions(datasette):
    return [
        Action(
            name=ADMIN_ACTION,
            description="Manage datasette-auth-basic-login accounts",
        )
    ]


@hookimpl
def permission_resources_sql(datasette, actor, action):
    """Self-answer the admin action: allow root, or an enabled admin row.

    Runs against the internal database (where the users table lives). Returns
    no rows for non-admins, so the action defaults to deny unless another
    provider (config allow / datasette-acl) grants it.
    """
    if action != ADMIN_ACTION:
        return None
    if not actor or not actor.get("id"):
        return None
    return PermissionSQL(
        sql=f"""
            SELECT NULL AS parent, NULL AS child, 1 AS allow,
                   'datasette-auth-basic-login: root' AS reason
            WHERE :actor_id = 'root'
            UNION ALL
            SELECT NULL, NULL, 1, 'datasette-auth-basic-login: is_admin'
            FROM {db.USERS}
            WHERE id = :actor_id AND {db.ENABLED_ADMIN_PREDICATE}
        """,
        # Must supply actor_id in params so core namespaces + binds it (an
        # empty/None params dict is dropped before the SQL runs).
        params={"actor_id": actor.get("id")},
    )


@hookimpl
def startup(datasette):
    async def inner():
        internal = datasette.get_internal_database()

        def migrate(conn):
            internal_migrations.apply(SqliteUtilsDatabase(conn))

        await internal.execute_write_fn(migrate)

        # Warn loudly when accounts won't persist (ephemeral internal DB).
        path = getattr(internal, "path", None) or ""
        if os.path.basename(path).startswith("datasette_temp_"):
            click.secho(
                "datasette-auth-basic-login: the internal database is EPHEMERAL — "
                "accounts and sessions will be lost on exit. Pass --internal "
                "path.db to persist them.",
                fg="yellow",
                err=True,
            )

        # Startup housekeeping: purge expired sessions + old audit rows.
        await db.delete_expired_sessions(internal)
        await db.purge_login_audit(
            internal, security.config(datasette, "audit_retention_days")
        )

    return inner


async def resolve_actor(datasette, request):
    """Rebuild the actor from the session cookie + DB, or return None.

    Shared by the actor_from_request hook and the asgi_wrapper forced-change
    gate, so the wrapper never depends on Datasette exposing the resolved actor.
    """
    cookie = request.cookies.get(COOKIE_NAME)
    if not cookie:
        return None
    try:
        raw_token = datasette.unsign(cookie, SIGN_NAMESPACE)
    except Exception:
        return None
    internal = datasette.get_internal_database()
    session = await db.get_session(internal, token_sha256(raw_token))
    if not session:
        return None
    if session["expires_at"] <= db.now_iso():
        await db.delete_session(internal, session["token_sha256"])
        return None
    user = await db.get_user_by_id(internal, session["actor_id"])
    if not user or user["disabled"]:
        return None
    await db.touch_last_seen(internal, session["token_sha256"], session["last_seen_at"])
    return {
        "id": user["id"],
        "username": user["username"],
        "is_admin": bool(user["is_admin"]),
        # Marker read by the asgi_wrapper forced-change gate.
        "must_change_password": bool(user["must_change_password"]),
    }


@hookimpl
def actor_from_request(datasette, request):
    async def inner():
        return await resolve_actor(datasette, request)

    return inner


@hookimpl
def menu_links(datasette, actor):
    async def inner():
        if not actor:
            return [{"href": datasette.urls.path("/-/login"), "label": "Log in"}]
        links = []
        if await datasette.allowed(action=ADMIN_ACTION, actor=actor):
            links.append(
                {
                    "href": datasette.urls.path("/-/admin/users"),
                    "label": "Accounts",
                }
            )
        links.append(
            {"href": datasette.urls.path("/-/account"), "label": "Your account"}
        )
        links.append(
            {"href": datasette.urls.path("/-/logout"), "label": "Log out"}
        )
        return links

    return inner


@hookimpl
def asgi_wrapper(datasette):
    """Enforce must_change_password globally.

    While the resolved actor has must_change_password set, allow only the
    account page + its change-password API, logout, login, and this plugin's
    static/Vite assets; redirect (HTML) or 403 (JSON) everything else.
    """

    def wrap(app):
        async def enforce(scope, receive, send):
            if scope["type"] != "http":
                await app(scope, receive, send)
                return

            from datasette.utils.asgi import Request

            request = Request(scope, receive)
            actor = await resolve_actor(datasette, request)
            if not actor or not actor.get("must_change_password"):
                await app(scope, receive, send)
                return

            path = scope.get("path", "")
            base = datasette.urls.path("/")
            if base != "/" and path.startswith(base):
                rel = path[len(base) - 1 :]
            else:
                rel = path
            if _forced_change_allowed(rel):
                await app(scope, receive, send)
                return

            accept = _header(scope, b"accept")
            account_url = datasette.urls.path("/-/account")
            if "application/json" in accept:
                await _send_json(
                    send, 403, {"ok": False, "error": "password change required"}
                )
            else:
                await _send_redirect(send, account_url)

        return enforce

    return wrap


_FORCED_CHANGE_PREFIXES = (
    "/-/account",
    "/-/logout",
    "/-/login",
    "/-/static/",
)


def _forced_change_allowed(path):
    if path.startswith("/-/static-plugins/"):
        return True
    return any(path == p or path.startswith(p) for p in _FORCED_CHANGE_PREFIXES)


def _header(scope, name):
    for key, value in scope.get("headers") or []:
        if key == name:
            return value.decode("latin-1")
    return ""


async def _send_json(send, status, payload):
    body = json.dumps(payload).encode("utf-8")
    await send(
        {
            "type": "http.response.start",
            "status": status,
            "headers": [[b"content-type", b"application/json"]],
        }
    )
    await send({"type": "http.response.body", "body": body})


async def _send_redirect(send, location):
    await send(
        {
            "type": "http.response.start",
            "status": 302,
            "headers": [[b"location", location.encode("latin-1")]],
        }
    )
    await send({"type": "http.response.body", "body": b""})


@hookimpl
def register_commands(cli):
    @cli.command(name="hash-password")
    @click.argument("password", required=False)
    def hash_password_command(password):
        """Hash a password with the datasette-auth-basic-login PBKDF2 scheme."""
        if not password:
            password = click.prompt(
                "Password", hide_input=True, confirmation_prompt=True
            )
        click.echo(hash_password(password))
