"""Cross-cutting security helpers: config, CSRF, redirect validation, cookies, IP.

CSRF protection is unconditional and lives here, not in reliance on any
Datasette middleware. See 03-authentication.md and 04-unconditional-csrf-checks.
"""

import re
from urllib.parse import unquote, urlparse

PLUGIN_NAME = "datasette-accounts"
COOKIE_NAME = "ds_accounts_session"
SIGN_NAMESPACE = "datasette-accounts"

DEFAULTS = {
    "session_ttl_days": 14,
    "password_min_length": 8,
    "lockout_threshold": 5,
    "lockout_minutes": 15,
    "secure_cookie": "auto",  # "auto" | True | False
    "audit_retention_days": 90,
    # Admin-audit trail retention; 0 = keep forever (the accountability
    # record is low-volume, unlike login attempts, so the safe default is the
    # opposite of audit_retention_days).
    "admin_audit_retention_days": 0,
    "trust_proxy_headers": False,  # trust X-Forwarded-* (proto + client IP)
    # --- Invite / reset links (see plans/invite-links) ---
    "invite_ttl_hours": 72,  # invite-link lifetime
    "reset_link_ttl_hours": 24,  # reset-link lifetime
    # --- Self-registration abuse caps (see plans/self-registration) ---
    # Both refuse with one generic message that never says which cap tripped.
    # These are config (deployment policy); the signups on/off switch itself
    # is runtime DB state, deliberately NOT config.
    "max_pending_registrations": 20,  # refuse signups while the queue is at cap
    "registrations_per_ip_per_day": 5,  # per-IP daily cap (client_ip; proxy trust applies)
    # --- Capability grants (F1) / acl bridge (F2) ---
    # Explicit allowlist of grantable global actions; None = auto-discover all
    # global (resource_class=None) actions minus the built-in denylist.
    "grantable_actions": None,
    # Extra action names to hide from auto-discovery.
    "grantable_actions_deny": [],
    # Actions for which the "everyone"/"anonymous" public audiences may be
    # granted. All other actions offer only "authenticated" (any signed-in user)
    # among the public principals, since the grantable set is write/create-heavy.
    "public_audience_actions": [],
    # Make accounts admins full datasette-acl admins (manage groups + all
    # resource sharing through acl's own UI). Set False to keep them separate.
    "grant_acl_admin": True,
}

_SCHEME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*:")

# --------------------------------------------------------------------------
# Username validation — public registration only
#
# Admin-created accounts (create_user, invite) go through no such check:
# admins are trusted, and existing deployments may already have usernames
# this rule would reject. The public self-registration surface (see
# plans/self-registration) needs a rule precisely because anyone can submit
# it. Loosening this later is easy; tightening it after accounts exist isn't.
# --------------------------------------------------------------------------

USERNAME_MIN_LENGTH = 3
USERNAME_MAX_LENGTH = 64
_USERNAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
# Case-insensitive: "Root"/"ROOT" would still collide with the bootstrap
# actor in anything that compares usernames loosely, and blocking the
# lookalikes closes an obvious impersonation trick.
_RESERVED_USERNAMES = frozenset({"root"})


def validate_username(username):
    """Return a human-readable rule violation, or None when `username` is valid.

    Same shape as `csrf_error`: a string means reject, None means proceed.
    Rules: 3-64 characters, `^[A-Za-z0-9][A-Za-z0-9._-]*$` (must start with a
    letter or digit), and the reserved name `root` (case-insensitively) is
    rejected.
    """
    if not username or not (
        USERNAME_MIN_LENGTH <= len(username) <= USERNAME_MAX_LENGTH
    ):
        return (
            f"Username must be {USERNAME_MIN_LENGTH}-{USERNAME_MAX_LENGTH} characters"
        )
    if not _USERNAME_RE.match(username):
        return (
            "Username may only contain letters, numbers, '.', '_', and '-', "
            "and must start with a letter or number"
        )
    if username.lower() in _RESERVED_USERNAMES:
        return "That username is reserved"
    return None


def config(datasette, key):
    plugin_config = datasette.plugin_config(PLUGIN_NAME) or {}
    return plugin_config.get(key, DEFAULTS[key])


# --------------------------------------------------------------------------
# CSRF / cross-origin — unconditional, applied to every mutation endpoint
# --------------------------------------------------------------------------


def csrf_error(request):
    """Return a human string if the request fails a CSRF gate, else None.

    1. Content-Type must be application/json (HTML forms cannot send it).
    2. If Sec-Fetch-Site is present it must be same-origin/none; else if Origin
       is present it must match the request host; else allow (non-browser).
    """
    content_type = (request.headers.get("content-type") or "").split(";")[0].strip()
    if content_type != "application/json":
        return "Content-Type must be application/json"

    sec_fetch_site = request.headers.get("sec-fetch-site")
    if sec_fetch_site is not None:
        if sec_fetch_site not in ("same-origin", "none"):
            return "Cross-site request rejected"
        return None

    origin = request.headers.get("origin")
    if origin:
        origin_host = urlparse(origin).netloc
        if origin_host and origin_host != request.host:
            return "Origin mismatch"
    return None


# --------------------------------------------------------------------------
# ?next= redirect validation
# --------------------------------------------------------------------------


def validate_next(next_value, base_url="/"):
    """Return a safe same-origin path, or the default ('/', or base_url).

    Rejects protocol-relative (//host), backslash tricks (/\\host), any scheme
    or authority, and CR/LF. Validates the URL-decoded value.
    """
    default = base_url or "/"
    if not next_value:
        return default
    decoded = unquote(next_value)
    if "\n" in decoded or "\r" in decoded:
        return default
    if "\\" in decoded:
        return default
    if not decoded.startswith("/"):
        return default
    if decoded.startswith("//"):
        return default
    if _SCHEME_RE.match(decoded):
        return default
    parsed = urlparse(decoded)
    if parsed.scheme or parsed.netloc:
        return default
    if base_url and base_url != "/" and not decoded.startswith(base_url):
        return default
    return decoded


# --------------------------------------------------------------------------
# Cookie Secure flag + client IP (share the proxy-trust signal)
# --------------------------------------------------------------------------


def _forwarded_proto_https(datasette, request):
    if not config(datasette, "trust_proxy_headers"):
        return False
    proto = request.headers.get("x-forwarded-proto") or ""
    return proto.split(",")[0].strip().lower() == "https"


def should_secure_cookie(datasette, request):
    setting = config(datasette, "secure_cookie")
    if setting is True:
        return True
    if setting is False:
        return False
    # "auto"
    if request.scheme == "https":
        return True
    return _forwarded_proto_https(datasette, request)


def client_ip(datasette, request):
    """Socket peer by default; first X-Forwarded-For hop only if proxy trusted."""
    if config(datasette, "trust_proxy_headers"):
        xff = request.headers.get("x-forwarded-for")
        if xff:
            return xff.split(",")[0].strip()
    scope = getattr(request, "scope", None) or {}
    client = scope.get("client")
    if client:
        return client[0]
    return None
