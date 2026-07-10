"""Provider mount — one route dispatching /-/login/provider/{key}/*.

datasette-plugin-router does not dispatch by HTTP method (CLAUDE.md gotcha): a
route registered once receives every method, so the dispatcher gates the method
itself. Each step in front of ``provider.handle`` is a central guarantee a
provider cannot opt out of (design §3).
"""

from datasette import Response

from .. import db, security
from ..providers import REGISTRY_ATTR
from ..router import router


@router.GET(r"/-/login/provider/(?P<key>[a-z0-9-]+)/(?P<rest>.*)$")
async def provider_dispatch(datasette, request, key: str, rest: str):
    registry = getattr(datasette, REGISTRY_ATTR, {})
    provider = registry.get(key)
    # An unknown provider and an installed-but-disabled provider 404 with the
    # *same* body: a disabled provider's whole URL surface (including mid-flight
    # callbacks) is dead, and we don't reveal which providers are installed but
    # off (design §3).
    if provider is None:
        return Response.text("Not found", status=404)
    internal = datasette.get_internal_database()
    if not await db.get_provider_enabled(internal, key):
        return Response.text("Not found", status=404)

    # Method gate. CSRF-gate POSTs before any provider code runs (mirrors
    # router._gate_mutation, which wraps csrf_error's string in a 403); only
    # GET/HEAD/POST reach a provider (OAuth callbacks GET, form providers POST).
    if request.method == "POST":
        problem = security.csrf_error(request)
        if problem:
            return Response.text(problem, status=403)
    elif request.method not in ("GET", "HEAD"):
        return Response.text("Method not allowed", status=405)

    return await provider.handle(datasette, request, rest)
