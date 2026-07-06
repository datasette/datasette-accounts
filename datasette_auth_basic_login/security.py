"""Cross-cutting security helpers: config, CSRF, redirect validation, cookies, IP.

CSRF protection is unconditional and lives here, not in reliance on any
Datasette middleware. See 03-authentication.md and 04-unconditional-csrf-checks.
"""

import re
from urllib.parse import unquote, urlparse

PLUGIN_NAME = "datasette-auth-basic-login"
COOKIE_NAME = "ds_auth_basic_login_session"
SIGN_NAMESPACE = "datasette-auth-basic-login"

DEFAULTS = {
    "session_ttl_days": 14,
    "password_min_length": 8,
    "lockout_threshold": 5,
    "lockout_minutes": 15,
    "secure_cookie": "auto",  # "auto" | True | False
    "audit_retention_days": 90,
    "trust_proxy_headers": False,  # trust X-Forwarded-* (proto + client IP)
}

_SCHEME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*:")


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
