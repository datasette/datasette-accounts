"""Shared Router instance and the auth/admin/CSRF decorators.

CSRF gates are unconditional and enforced here for every state-changing method
(anything that is not a safe GET/HEAD). See security.csrf_error.
"""

from functools import wraps

from datasette import Forbidden, Response
from datasette_plugin_router import Router

from . import security

router = Router(title="datasette-accounts", version="0.1a0")

ADMIN_ACTION = "datasette-accounts-admin"


def _json_error(message, status):
    return Response.json({"ok": False, "error": message}, status=status)


def _gate_mutation(request):
    """Reject anything that is not a CSRF-clean POST.

    datasette-plugin-router does not dispatch by HTTP method, so a POST-only
    view still receives GET/HEAD/etc. Enforcing POST here closes the
    "GET triggers the mutation and skips CSRF" hole; then apply the CSRF gates
    unconditionally (never treat a method as exempt).
    """
    if request.method != "POST":
        return _json_error("Method not allowed", 405)
    problem = security.csrf_error(request)
    if problem:
        return _json_error(problem, 403)
    return None


def require_csrf(func):
    """CSRF gate only (used by the anonymous authenticate endpoint)."""

    @wraps(func)
    async def wrapper(datasette, request, **kwargs):
        blocked = _gate_mutation(request)
        if blocked:
            return blocked
        return await func(datasette=datasette, request=request, **kwargs)

    return wrapper


def require_actor(func):
    """CSRF gate + an authenticated actor (any user). JSON errors."""

    @wraps(func)
    async def wrapper(datasette, request, **kwargs):
        blocked = _gate_mutation(request)
        if blocked:
            return blocked
        if not request.actor:
            return _json_error("Authentication required", 401)
        return await func(datasette=datasette, request=request, **kwargs)

    return wrapper


def require_admin(func):
    """CSRF gate + the admin action. JSON errors (for the /-/admin/api routes)."""

    @wraps(func)
    async def wrapper(datasette, request, **kwargs):
        blocked = _gate_mutation(request)
        if blocked:
            return blocked
        if not await datasette.allowed(action=ADMIN_ACTION, actor=request.actor):
            return _json_error("Admin permission required", 403)
        return await func(datasette=datasette, request=request, **kwargs)

    return wrapper


def require_admin_page(func):
    """The admin action for an HTML page — raises Forbidden on failure."""

    @wraps(func)
    async def wrapper(datasette, request, **kwargs):
        if not await datasette.allowed(action=ADMIN_ACTION, actor=request.actor):
            raise Forbidden("Admin permission required")
        return await func(datasette=datasette, request=request, **kwargs)

    return wrapper
