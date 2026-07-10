"""Admin-editable site messages: the registry of slots + HTML rendering.

Admins write into a fixed set of *slots* (see ``SITE_MESSAGE_SLOTS``); each slot
is surfaced at a known place in the running app — a sign-in prompt on the
homepage, a help/contact note on the login page, and so on. The DB only ever
stores ``key -> body`` for these keys (``db.set_site_message`` rejects unknown
keys); everything about *where* and *to whom* a slot renders lives here.

Bodies are rendered as **raw HTML, verbatim** so an admin can include links
(``<a href="mailto:...">``), emphasis, etc. This is deliberately unescaped:
only admins can set a message, and an accounts admin already has
template/permission-level trust, so message HTML is treated as first-party.
Never surface this text to a non-admin editor.
"""

import markupsafe

# Longest body we accept, to keep a slot from becoming an unbounded blob.
MAX_BODY_LENGTH = 4000

# Ordered registry of every message slot. `audience` documents who sees the
# slot when it is rendered by a hook (the login-page slot is passed through page
# data instead, so its audience is implicit — anyone on the login page).
SITE_MESSAGE_SLOTS = [
    {
        "key": "homepage_signed_out",
        "label": "Homepage sign-in prompt",
        "description": (
            "Shown at the top of the Datasette homepage to visitors who are "
            "not signed in — e.g. a note prompting them to log in."
        ),
        "audience": "anonymous",
    },
    {
        "key": "login_help",
        "label": "Login help / contact",
        "description": (
            "Shown on the login page — e.g. who to contact when someone can't "
            'sign in ("Email alice@corp.com for access").'
        ),
        "audience": "login-page",
    },
    {
        "key": "register_help",
        "label": "Registration help",
        "description": (
            "Shown on the registration page (see plans/self-registration) — "
            "e.g. what happens after signing up or who to contact with "
            'questions ("An admin reviews requests within one business day").'
        ),
        "audience": "register-page",
    },
]

SLOT_KEYS = frozenset(slot["key"] for slot in SITE_MESSAGE_SLOTS)


def is_slot(key):
    return key in SLOT_KEYS


async def slots_view(internal):
    """The Messages admin page/API payload: every slot with its current body."""
    from . import db

    stored = await db.get_site_messages(internal)
    return {
        "slots": [
            {
                "key": slot["key"],
                "label": slot["label"],
                "description": slot["description"],
                "body": stored.get(slot["key"], ""),
            }
            for slot in SITE_MESSAGE_SLOTS
        ]
    }


def render_message(body):
    """Return a stored body as raw (unescaped) markup for embedding in a slot.

    Bodies are admin-authored HTML — see the module docstring on why they are
    trusted and NOT escaped. Empty/blank bodies return an empty Markup.
    """
    if not body or not body.strip():
        return markupsafe.Markup("")
    return markupsafe.Markup(body.strip())
