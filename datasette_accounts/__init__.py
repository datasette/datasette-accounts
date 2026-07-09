import json
import os

import click
import markupsafe
from datasette import hookimpl
from datasette.permissions import Action, PermissionSQL
from datasette_vite import vite_entry
from sqlite_utils import Database as SqliteUtilsDatabase

from . import db, messages, security
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
        plugin_package="datasette_accounts",
    )
    return {"datasette_accounts_vite_entry": entry}


@hookimpl
def register_actions(datasette):
    return [
        Action(
            name=ADMIN_ACTION,
            description="Manage datasette-accounts accounts",
        )
    ]


_ADMIN_ALLOW_SQL = f"""
    SELECT NULL AS parent, NULL AS child, 1 AS allow,
           'datasette-accounts: root' AS reason
    WHERE :actor_id = 'root'
    UNION ALL
    SELECT NULL, NULL, 1, 'datasette-accounts: is_admin'
    FROM {db.USERS}
    WHERE id = :actor_id AND {db.ENABLED_ADMIN_PREDICATE}
"""


def _capability_grant_sql(has_acl):
    """SQL emitting allow rows for a global action from the grants table.

    Actor + public-audience clauses always; the group clause only when acl's
    membership table exists (referencing a missing table would fail to compile).
    """
    sql = f"""
        SELECT NULL AS parent, NULL AS child, 1 AS allow,
               'datasette-accounts: capability grant' AS reason
        FROM {db.CAPABILITY_GRANTS}
        WHERE action = :cap_action
          AND (
              (principal_type = 'actor' AND actor_id = :actor_id)
              OR principal_type = 'everyone'
              OR (principal_type = 'authenticated' AND :actor_id IS NOT NULL)
              OR (principal_type = 'anonymous' AND :actor_id IS NULL)
          )
    """
    if has_acl:
        sql += f"""
        UNION ALL
        SELECT NULL, NULL, 1, 'datasette-accounts: capability grant (group)'
        FROM {db.CAPABILITY_GRANTS} g
        JOIN {db.ACL_ACTOR_GROUPS} ag
            ON ag.group_id = g.group_id AND ag.actor_id = :actor_id
        JOIN {db.ACL_GROUPS} gr ON gr.id = g.group_id AND gr.deleted IS NULL
        WHERE g.action = :cap_action AND g.principal_type = 'group'
        """
    return sql


@hookimpl
def permission_resources_sql(datasette, actor, action):
    """Contribute allow rows against the internal database:

    - the ``datasette-accounts-admin`` action (root or enabled admin) — self;
    - the ``datasette-acl`` action for admins when ``grant_acl_admin`` is set,
      so accounts admins manage groups + resource sharing via acl's UI (F2);
    - any **global** action that has capability grants in our table (F1).

    Allow-only: this hook never emits a deny, so grants compose additively with
    config-permissions and datasette-acl.
    """
    actor_id = actor.get("id") if actor else None

    async def inner():
        results = []

        if action == ADMIN_ACTION:
            results.append(
                PermissionSQL(sql=_ADMIN_ALLOW_SQL, params={"actor_id": actor_id})
            )

        if action == "datasette-acl" and security.config(datasette, "grant_acl_admin"):
            results.append(
                PermissionSQL(
                    sql=_ADMIN_ALLOW_SQL.replace(
                        "datasette-accounts: root",
                        "datasette-accounts: admin (acl bridge)",
                    ).replace(
                        "datasette-accounts: is_admin",
                        "datasette-accounts: admin (acl bridge)",
                    ),
                    params={"actor_id": actor_id},
                )
            )

        # F1 — only global actions can carry capability grants (validated on
        # write), so skip the table read for the far more frequent
        # resource-scoped checks (view-table, etc.).
        action_obj = datasette.actions.get(action)
        if (
            action_obj is not None
            and getattr(action_obj, "resource_class", None) is None
        ):
            internal = datasette.get_internal_database()
            has_acl = await db.acl_available(internal)
            results.append(
                PermissionSQL(
                    sql=_capability_grant_sql(has_acl),
                    params={"actor_id": actor_id, "cap_action": action},
                )
            )

        return results or None

    return inner


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
                "datasette-accounts: the internal database is EPHEMERAL — "
                "accounts and sessions will be lost on exit. Pass --internal "
                "path.db to persist them.",
                fg="yellow",
                err=True,
            )

        # Startup housekeeping: purge expired sessions, expired password
        # tokens, and old audit rows.
        await db.delete_expired_sessions(internal)
        await db.purge_expired_password_tokens(internal)
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
    if user["expires_at"] and user["expires_at"] <= db.now_iso():
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
def datasette_acl_valid_actors(datasette):
    """Expose accounts users to datasette-acl (F3).

    Lets acl's group-member picker and share dialog validate + autocomplete
    accounts by username. Never called when acl isn't installed (its hookspec
    is absent), so this is inert in that case.
    """

    async def inner():
        internal = datasette.get_internal_database()
        rows = await db.list_users(internal)
        now = db.now_iso()
        return [
            {"id": r["id"], "display": r["username"]}
            for r in rows
            if not r["disabled"] and not (r["expires_at"] and r["expires_at"] <= now)
        ]

    return inner


def _banner(body, *, tone="info"):
    """A self-contained notice for the homepage slot (no external CSS needed).

    ``body`` must already be safe markup (escaped). ``tone`` picks the accent.
    """
    accent = "#b45309" if tone == "warn" else "#1d4ed8"
    bg = "#fffbeb" if tone == "warn" else "#eff6ff"
    return markupsafe.Markup(
        '<div style="margin:0 0 1rem;padding:0.75rem 1rem;border:1px solid '
        f"{accent}33;border-left:4px solid {accent};border-radius:6px;"
        f'background:{bg};color:#1f2937;font-size:0.95rem;line-height:1.5">'
        f"{body}</div>"
    )


@hookimpl
def top_homepage(datasette, request):
    """Homepage notices:

    1. Bootstrap prompt — while signed in as ``root`` and no enabled admin
       account exists yet, prompt root to create the first admin (after which
       root is no longer needed). See plans/site-messages.
    2. The admin-authored ``homepage_signed_out`` message, shown only to
       visitors who are not signed in.
    """

    async def inner():
        actor = getattr(request, "actor", None)
        internal = datasette.get_internal_database()
        bits = []

        if actor and actor.get("id") == "root":
            if await db.count_enabled_admins(internal) == 0:
                users_url = datasette.urls.path("/-/admin/users")
                bits.append(
                    _banner(
                        markupsafe.Markup(
                            "You're signed in as <strong>root</strong>. "
                            "Create the first admin account to finish setup — "
                            "after that, root is no longer required. "
                            f'<a href="{markupsafe.escape(users_url)}">'
                            "Create an admin account →</a>"
                        ),
                        tone="warn",
                    )
                )

        if not actor:
            body = await db.get_site_message(internal, "homepage_signed_out")
            rendered = messages.render_message(body)
            if rendered:
                bits.append(_banner(rendered))

        if not bits:
            return None
        return markupsafe.Markup("".join(bits))

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
                {
                    "href": datasette.urls.path("/-/admin/capabilities"),
                    "label": "Capabilities",
                }
            )
            links.append(
                {
                    "href": datasette.urls.path("/-/admin/messages"),
                    "label": "Messages",
                }
            )
            links.append(
                {
                    "href": datasette.urls.path("/-/admin/login-attempts"),
                    "label": "Login attempts",
                }
            )
            # F2 — admins are acl admins, so link to acl's group + sharing UI
            # when acl is installed.
            if await db.acl_available(datasette.get_internal_database()):
                links.append(
                    {
                        "href": datasette.urls.path("/-/acl/groups"),
                        "label": "Groups & sharing",
                    }
                )
        links.append(
            {"href": datasette.urls.path("/-/account"), "label": "Your account"}
        )
        links.append({"href": datasette.urls.path("/-/logout"), "label": "Log out"})
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
    from .cli import accounts

    cli.add_command(accounts)

    # Deprecated top-level alias for `datasette accounts hash-password`, kept for
    # one release. Emits a stderr notice, then delegates to the same code.
    @cli.command(name="hash-password")
    @click.argument("password", required=False)
    def hash_password_command(password):
        """Hash a password (deprecated: use `datasette accounts hash-password`)."""
        click.secho(
            "Warning: `datasette hash-password` is deprecated — use "
            "`datasette accounts hash-password`.",
            fg="yellow",
            err=True,
        )
        if not password:
            password = click.prompt(
                "Password", hide_input=True, confirmation_prompt=True
            )
        click.echo(hash_password(password))
