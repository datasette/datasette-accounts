"""Which global actions an admin may grant, and to which principals.

Capability grants (F1) only ever target **global** actions — Datasette actions
with ``resource_class is None``. Resource-scoped actions (paper-view, places-edit,
table ACLs, …) belong to datasette-acl and are never surfaced here.

Discovery is either an explicit ``grantable_actions`` allowlist or auto-discovery
of every global action minus a built-in denylist (core Datasette internals, our
own admin action, and the datasette-acl super-permission — that one is managed by
the F2 bridge, not granted row-by-row).
"""

import json

from . import db, security
from .router import ADMIN_ACTION

# Global actions never offered for row-by-row granting:
#   - core Datasette internals a permission UI shouldn't hand out casually;
#   - ADMIN_ACTION — accounts admin is managed by the is_admin flag, not grants;
#   - datasette-acl — the acl super-permission, handled by the F2 bridge instead.
DEFAULT_DENY = frozenset(
    {
        "view-instance",
        "execute-sql",
        "permissions-debug",
        "debug-menu",
        ADMIN_ACTION,
        "datasette-acl",
    }
)


def grantable_actions(datasette):
    """Ordered list of the ``Action`` objects an admin may grant.

    Global actions only. With ``grantable_actions`` configured, exactly those
    (that exist and are global); otherwise every global action minus
    ``DEFAULT_DENY`` and the configured ``grantable_actions_deny``.
    """
    allow = security.config(datasette, "grantable_actions")
    allow = set(allow) if allow is not None else None
    deny = set(security.config(datasette, "grantable_actions_deny") or [])
    actions = []
    for name, action in sorted(datasette.actions.items()):
        if getattr(action, "resource_class", None) is not None:
            continue
        if allow is not None:
            if name not in allow:
                continue
        elif name in DEFAULT_DENY or name in deny:
            continue
        actions.append(action)
    return actions


def grantable_names(datasette):
    return {a.name for a in grantable_actions(datasette)}


def is_grantable(datasette, action_name):
    return action_name in grantable_names(datasette)


def offerable_principals(datasette, action_name, has_acl):
    """Principal kinds an admin may target for this action.

    Always ``actor`` + ``authenticated``; ``group`` only when acl is installed;
    ``everyone``/``anonymous`` only for actions explicitly marked read-safe via
    ``public_audience_actions`` (D11 — the grantable set is write-heavy).
    """
    principals = ["actor"]
    if has_acl:
        principals.append("group")
    principals.append("authenticated")
    if action_name in set(security.config(datasette, "public_audience_actions") or []):
        principals += ["everyone", "anonymous"]
    return principals


def principal_offerable(datasette, action_name, principal_type, has_acl):
    return principal_type in offerable_principals(datasette, action_name, has_acl)


def action_info(action):
    """Serialisable view of an Action for the UI / page data."""
    return {
        "name": action.name,
        "description": action.description or "",
        "also_requires": getattr(action, "also_requires", None),
    }


async def grantable_view(datasette, internal):
    """Assemble the full Capabilities page/API payload.

    Returns ``{actions, groups, has_acl}`` where each action carries its current
    table grants and offerable principals. Config-sourced grants (D8) are added
    per action from ``config_grants_for``.
    """
    has_acl = await db.acl_available(internal)
    actions = grantable_actions(datasette)
    names = [a.name for a in actions]
    grants = await db.list_capability_grants(internal, actions=names)
    by_action = {}
    for g in grants:
        by_action.setdefault(g["action"], []).append(g)
    groups = await db.list_acl_groups(internal)
    payload = []
    for action in actions:
        info = action_info(action)
        info["grants"] = by_action.get(action.name, [])
        info["offerable_principals"] = offerable_principals(
            datasette, action.name, has_acl
        )
        info["config_grants"] = config_grants_for(datasette, action.name)
        payload.append(info)
    return {"actions": payload, "groups": groups, "has_acl": has_acl}


def config_grants_for(datasette, action_name):
    """Read-only view of datasette.yaml grants for an action (D8).

    Datasette resolves ``permissions:``/``allow:`` blocks against actor
    *attributes*, so we cannot always enumerate the affected users — we surface
    the raw block that applies to the action (or an opaque marker for
    ``allow_sql``) so an admin sees *why* a capability is in effect even after
    revoking every table grant. Returns a list of ``{source, allow}`` entries.
    """
    config = datasette.config or {}
    permissions = config.get("permissions") or {}
    out = []
    block = permissions.get(action_name)
    if block is not None:
        # Pretty-printed JSON so the UI can render it verbatim without needing
        # to type an arbitrary allow-block shape.
        out.append({"source": "permissions", "allow_json": json.dumps(block, indent=2)})
    return out
