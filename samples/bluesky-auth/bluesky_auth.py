"""Sample Bluesky (AT Protocol) sign-in provider for datasette-accounts.

Unlike the plain-OAuth2 samples (Discord, GitHub — a registered app with a
client secret), atproto OAuth has no client secret at all: it is a **public**
client (``token_endpoint_auth_method: "none"``) whose ``client_id`` is a URL
to a client-metadata JSON document THIS app serves itself (see
``client_metadata`` below). PAR + PKCE + DPoP are all mandatory, and identity
resolution (handle -> DID -> PDS -> auth server) happens before the visitor is
ever redirected to an authorize page. Sign-in only, by design: access/refresh
tokens are discarded right after the callback verifies identity — no token
store, no refresh, no PDS writes (see ``todos/bluesky-auth/README.md``). It is
a single loose module that Datasette's ``--plugins-dir`` imports directly (no
packaging); ``just dev`` loads it via ``samples/dev-plugins``.

This ticket (01) only scaffolds the provider: the descriptor, the
client-metadata route, and a SQL table (created idempotently by this module's
own ``startup`` hookimpl — a loose sample can't append rows to core's
``internal_migrations.py``) that will hold each flow's PKCE verifier and
per-flow DPoP private key. ``start`` and ``callback`` are 501 stubs; tickets
02-04 fill in DPoP/identity helpers, the PAR + redirect, and the token
exchange + verification.

Setup:

1. Pick a mode (mutually exclusive; public wins if both are set):
   - Production: export ``DATASETTE_BLUESKY_PUBLIC_URL`` to this instance's
     public HTTPS origin (e.g. ``https://data.example.com``) — an auth server
     must be able to fetch
     ``{PUBLIC_URL}/-/bluesky-auth/client-metadata.json`` anonymously during
     PAR.
   - Local dev: export ``DATASETTE_BLUESKY_DEV_LOOPBACK=1`` instead. Uses
     atproto's "loopback client" (``client_id = "http://localhost?..."``) —
     no metadata hosting needed; real auth servers (bsky.social) special-case
     this form.
   - Neither set -> ``configured()`` is False: core hides the login button
     (and link/step-up targets), and ``start`` will 503 once ticket 03 lands —
     the same inert-when-unconfigured contract as the other OAuth samples.
2. Enable + open the provider (external providers are disabled by default):
       datasette accounts enable-provider bluesky -i accounts.db
       datasette accounts set-signups bluesky auto -i accounts.db   # or approval

There is no client secret to export: atproto is a public-client protocol —
the client-metadata document IS the client's registration, not a bearer
secret. See README.md (ticket 05) for the full protocol walkthrough.
"""

from __future__ import annotations

import base64
import hashlib
import os
import secrets
import time
import urllib.parse
from typing import TYPE_CHECKING

import httpx
from authlib.jose import JsonWebKey, jwt
from datasette import Response, hookimpl

from datasette_accounts.providers import AuthProvider, provider_gate

if TYPE_CHECKING:
    from datasette.app import Datasette
    from datasette.utils.asgi import Request

# The sample's own flow table (design note: no core internal_migrations.py
# entry — a loose plugins_dir module can't add one). Keyed by the core signed
# state nonce so a flow row and its cookie expire together; ticket 02/03 write
# to it, ticket 04 reads + deletes it.
FLOW_TABLE = "bluesky_auth_oauth_flows"

_CREATE_FLOW_TABLE = f"""
CREATE TABLE IF NOT EXISTS {FLOW_TABLE} (
    state TEXT PRIMARY KEY,          -- core signed-state nonce (State["s"])
    did TEXT,                        -- expected DID; NULL for default-server starts
    issuer TEXT NOT NULL,            -- auth server the user was sent to
    pkce_verifier TEXT NOT NULL,
    dpop_private_jwk TEXT NOT NULL,  -- per-flow P-256 private key, JSON
    dpop_nonce TEXT,                 -- last DPoP-Nonce the server issued
    created_at TEXT NOT NULL         -- strftime millisecond-ISO + '+00:00'
)
"""


class BlueskyProvider(AuthProvider):
    """Sign in with Bluesky (AT Protocol OAuth, public client).

    ``start`` (ticket 03) resolves the visitor's identity, PARs against their
    auth server with a fresh PKCE/DPoP pair, and redirects there carrying the
    core-minted signed ``state``; ``callback`` (ticket 04) exchanges the code
    for a token, cross-checks the issuer, and hands core an
    ``ExternalIdentity`` keyed on the DID (never the handle — mutable and
    transferable — and never an email, which atproto doesn't expose). The
    provider owns its own routes under ``/-/bluesky-auth/...`` (registered
    below); ``start_path`` is where the login button + link/step-up point.
    """

    key = "bluesky"
    label = "Bluesky"
    start_path = "/-/bluesky-auth/start"
    # Login-button branding: Bootstrap Icons' butterfly mark (bi-bluesky,
    # MIT — https://github.com/twbs/icons, same license as the GitHub sample's
    # bi-github at github_auth.py:68-70) with fill="currentColor" so it
    # inherits the button's white text, plus Bluesky's brand blue background.
    icon = (
        '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" '
        'fill="currentColor" class="bi bi-bluesky" viewBox="0 0 16 16">'
        '<path d="M3.468 1.948C5.303 3.325 7.276 6.118 8 7.616c.725-1.498 '
        "2.698-4.29 4.532-5.668C13.855.955 16 .186 16 2.632c0 .489-.28 "
        "4.105-.444 4.692-.572 2.04-2.653 2.561-4.504 2.246 3.236.551 4.06 "
        "2.375 2.281 4.2-3.376 3.464-4.852-.87-5.23-1.98-.07-.204-.103-.3"
        "-.103-.218 0-.081-.033.014-.102.218-.379 1.11-1.855 5.444-5.231 "
        "1.98-1.778-1.825-.955-3.65 2.28-4.2-1.85.315-3.932-.205-4.503"
        '-2.246C.28 6.737 0 3.12 0 2.632 0 .186 2.145.955 3.468 1.948"/>'
        "</svg>"
    )
    brand_color = "#1185FE"

    def configured(self, datasette: Datasette) -> bool:
        # Ready to authenticate once one of the two mutually-exclusive modes
        # is configured. Until then the login button + link targets hide it
        # (core respects this), and `start` will 503 as defense in depth
        # (ticket 03) if someone hits it directly.
        return _mode() is not None


def _public_url() -> str | None:
    return os.environ.get("DATASETTE_BLUESKY_PUBLIC_URL")


def _mode() -> str | None:
    # Public wins if both are set — a production deployment that also leaves
    # the dev flag set should still behave like production.
    if _public_url():
        return "public"
    if os.environ.get("DATASETTE_BLUESKY_DEV_LOOPBACK") == "1":
        return "loopback"
    return None


def _redirect_uri(datasette: Datasette, request: Request) -> str:
    # client_id and redirect_uri must be byte-identical everywhere they are
    # sent (client-metadata document, PAR, token exchange) — this is the one
    # place either is built.
    if _mode() == "public":
        return _public_url().rstrip("/") + datasette.urls.path(
            "/-/bluesky-auth/callback"
        )
    # Loopback (spec): the redirect_uri host must be the literal IP 127.0.0.1
    # (or [::1]) — NOT "localhost" — while the client_id host below is the
    # literal string "localhost". absolute_url reflects whatever host the
    # visitor's browser actually used (localhost, 127.0.0.1, a LAN IP...), so
    # force it, keeping whatever port that host carried.
    absolute = datasette.absolute_url(
        request, datasette.urls.path("/-/bluesky-auth/callback")
    )
    parsed = urllib.parse.urlsplit(absolute)
    netloc = "127.0.0.1" if parsed.port is None else f"127.0.0.1:{parsed.port}"
    return urllib.parse.urlunsplit(parsed._replace(netloc=netloc))


def _client_id(datasette: Datasette, request: Request) -> str:
    if _mode() == "public":
        return _public_url().rstrip("/") + datasette.urls.path(
            "/-/bluesky-auth/client-metadata.json"
        )
    # Loopback client (spec): no metadata hosting needed at all — the
    # client_id itself encodes redirect_uri + scope. Real auth servers
    # (bsky.social) special-case this exact "http://localhost?..." form.
    return "http://localhost?" + urllib.parse.urlencode(
        {"redirect_uri": _redirect_uri(datasette, request), "scope": "atproto"}
    )


def _public_origin(datasette: Datasette, request: Request) -> str:
    # client_uri in the metadata document: an origin to show the user, not a
    # protocol-load-bearing value. In loopback mode client-metadata.json is
    # never actually fetched by a real auth server (the client_id already IS
    # the metadata), so any well-formed origin is harmless here.
    if _mode() == "public":
        return _public_url().rstrip("/")
    absolute = datasette.absolute_url(request, datasette.urls.path("/"))
    parsed = urllib.parse.urlsplit(absolute)
    return f"{parsed.scheme}://{parsed.netloc}"


# ==========================================================================
# Protocol helpers (atproto OAuth: DPoP + PKCE + identity resolution)
#
# There is no @atproto/oauth-client-node equivalent among this repo's Python
# deps, so the three mechanics plain OAuth2 lacks are hand-rolled here. Field
# names + endpoints: todos/bluesky-auth/README.md "Protocol cheat sheet";
# arbiters are https://atproto.com/specs/oauth and bluesky-social/cookbook ->
# python-oauth-web-app (which also uses authlib). Every helper is pure enough
# to unit-test without a Datasette instance (tests/test_bluesky_sample.py); the
# httpx-using ones take the client as a parameter so tests pass a fake.
# ==========================================================================

# Unauthenticated appview shortcut for handle -> DID (spec cheat sheet); the
# trustless DNS-TXT/.well-known path is a documented non-goal (ticket 05).
RESOLVE_HANDLE_URL = (
    "https://public.api.bsky.app/xrpc/com.atproto.identity.resolveHandle"
)
# did:plc documents are served by the PLC directory.
PLC_DIRECTORY_URL = "https://plc.directory"


class FlowError(Exception):
    """Any resolution failure / malformed protocol document. Tickets 03/04
    catch this single type and answer a generic 400 (never leak internals)."""


def _require_https(url: str) -> str:
    """Reject non-HTTPS endpoint URLs (SSRF hygiene, matching npmx's avatar
    fetch). Deliberate simplification: no http://localhost carve-out. This
    sign-in-only sample never reaches a developer's local PDS — even loopback
    dev authenticates against the real bsky.social auth server over https — so
    requiring https everywhere keeps the check trivial and closes the hole."""
    if not isinstance(url, str) or not url.startswith("https://"):
        raise FlowError(f"refusing non-HTTPS endpoint URL: {url!r}")
    return url


def _gen_dpop_jwk() -> dict:
    """Fresh per-flow P-256 private key as a JWK dict (JSON-serializable for
    the flow row's dpop_private_jwk column). Cheat sheet: "DPoP proof JWT"."""
    key = JsonWebKey.generate_key("EC", "P-256", is_private=True)
    return key.as_dict(is_private=True)


def _dpop_proof(
    private_jwk: dict, method: str, url: str, nonce: str | None = None
) -> str:
    """One ES256 DPoP proof JWT for a single PAR/token POST. The header's `jwk`
    is the PUBLIC half only — as_dict(is_private=False) drops the private
    scalar `d`; leaking it would hand out the flow's signing key. `htu` is the
    request URL with query/fragment stripped, per the spec. `ath` is omitted:
    it is only for resource requests carrying an access token, which this
    sign-in-only sample never makes."""
    key = JsonWebKey.import_key(private_jwk)
    header = {
        "typ": "dpop+jwt",
        "alg": "ES256",
        "jwk": key.as_dict(is_private=False),  # public half only — never `d`
    }
    claims = {
        "jti": secrets.token_urlsafe(16),
        "htm": method,
        "htu": url.split("?", 1)[0],  # no query/fragment
        "iat": int(time.time()),
    }
    if nonce:
        claims["nonce"] = nonce
    return jwt.encode(header, claims, key).decode()


def _pkce_pair() -> tuple[str, str]:
    """(verifier, S256 challenge). Verifier length (48 url-safe bytes -> 64
    chars) sits inside RFC 7636's 43-128 range; challenge is unpadded
    base64url(sha256(verifier))."""
    verifier = secrets.token_urlsafe(48)
    challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
        .rstrip(b"=")
        .decode()
    )
    return verifier, challenge


async def _post_with_dpop(
    client, private_jwk: dict, url: str, data: dict, nonce: str | None = None
) -> tuple[httpx.Response, str | None]:
    """POST form `data` with a DPoP proof; used by PAR (03) and the token
    exchange (04). A 4xx JSON body {"error": "use_dpop_nonce"} is the NORMAL
    path (bsky.social always demands a server nonce), not an error: retry ONCE
    with the DPoP-Nonce response header folded into the proof. Returns
    (response, latest_nonce) so callers persist the freshest nonce on the flow
    row. No raise_for_status here — callers gate on the body (the GitHub
    sample's errors-as-200 lesson, github_auth.py:182-187)."""
    proof = _dpop_proof(private_jwk, "POST", url, nonce=nonce)
    resp = await client.post(url, data=data, headers={"DPoP": proof})
    latest = resp.headers.get("DPoP-Nonce", nonce)
    if 400 <= resp.status_code < 500 and "DPoP-Nonce" in resp.headers:
        try:
            body = resp.json()
        except Exception:
            body = {}
        if body.get("error") == "use_dpop_nonce":
            server_nonce = resp.headers["DPoP-Nonce"]
            proof = _dpop_proof(private_jwk, "POST", url, nonce=server_nonce)
            resp = await client.post(url, data=data, headers={"DPoP": proof})
            latest = resp.headers.get("DPoP-Nonce", server_nonce)
    return resp, latest


async def _resolve_handle(client, handle: str) -> str:
    """Handle -> DID via the appview's resolveHandle. Cheat sheet:
    "Handle -> DID"."""
    resp = await client.get(RESOLVE_HANDLE_URL, params={"handle": handle})
    if resp.status_code != 200:
        raise FlowError(f"could not resolve handle {handle!r}")
    did = resp.json().get("did")
    if not did:
        raise FlowError(f"no DID for handle {handle!r}")
    return did


async def _did_doc(client, did: str) -> dict:
    """DID -> DID document. Supports did:plc (GET plc.directory/<did>, the DID
    percent-encoded) and did:web:<host> (GET https://<host>/.well-known/
    did.json). did:web is restricted to the plain-host form — DIDs with path
    segments (further ':' parts) are rejected to keep the sample simple. Any
    other method raises. Cheat sheet: "DID -> DID document"."""
    if did.startswith("did:plc:"):
        url = f"{PLC_DIRECTORY_URL}/{urllib.parse.quote(did, safe='')}"
    elif did.startswith("did:web:"):
        host = did[len("did:web:") :]
        if not host or ":" in host:  # reject path form did:web:host:path...
            raise FlowError(f"unsupported did:web form (path segments): {did!r}")
        url = f"https://{host}/.well-known/did.json"
    else:
        raise FlowError(f"unsupported DID method: {did!r}")
    resp = await client.get(url)
    if resp.status_code != 200:
        raise FlowError(f"DID document fetch failed for {did!r}")
    return resp.json()


def _pds_endpoint(did_doc: dict) -> str:
    """PDS endpoint = the `service` entry whose `id` ends with '#atproto_pds'
    (type AtprotoPersonalDataServer). https-only (_require_https). Cheat sheet:
    "DID doc -> PDS"."""
    for svc in did_doc.get("service") or []:
        if str(svc.get("id", "")).endswith("#atproto_pds"):
            return _require_https(svc.get("serviceEndpoint"))
    raise FlowError("no #atproto_pds service in DID document")


def _handle_from_did_doc(did_doc: dict) -> str | None:
    """Handle from alsoKnownAs[0] ('at://<handle>' -> '<handle>'), or None. A
    non-authoritative convenience for display; the authoritative subject is the
    DID. Cheat sheet: "DID doc -> PDS" (alsoKnownAs note)."""
    aka = did_doc.get("alsoKnownAs") or []
    if aka and isinstance(aka[0], str) and aka[0].startswith("at://"):
        return aka[0][len("at://") :]
    return None


async def _resolve_authserver(client, pds_url: str) -> str:
    """PDS -> authorization-server issuer via the protected-resource metadata.
    Cheat sheet: "PDS -> auth server"."""
    url = pds_url.rstrip("/") + "/.well-known/oauth-protected-resource"
    resp = await client.get(url)
    if resp.status_code != 200:
        raise FlowError(f"protected-resource metadata fetch failed for {pds_url!r}")
    servers = resp.json().get("authorization_servers") or []
    if not servers:
        raise FlowError(f"no authorization_servers for PDS {pds_url!r}")
    return _require_https(servers[0])


async def _authserver_metadata(client, issuer: str) -> dict:
    """Auth-server metadata (PAR/authorize/token endpoints). Spec self-
    consistency check: the document's `issuer` MUST equal the URL it was
    fetched from, and all three endpoints must be https. Cheat sheet: "Auth
    server metadata"."""
    url = issuer.rstrip("/") + "/.well-known/oauth-authorization-server"
    resp = await client.get(url)
    if resp.status_code != 200:
        raise FlowError(f"auth-server metadata fetch failed for {issuer!r}")
    meta = resp.json()
    if meta.get("issuer") != issuer:
        raise FlowError(
            f"auth-server metadata issuer mismatch: {meta.get('issuer')!r} != {issuer!r}"
        )
    for field in (
        "pushed_authorization_request_endpoint",
        "authorization_endpoint",
        "token_endpoint",
    ):
        if field not in meta:
            raise FlowError(f"auth-server metadata missing {field}")
        _require_https(meta[field])
    return meta


@provider_gate("bluesky")
async def client_metadata(datasette: Datasette, request: Request) -> Response:
    # Fetched anonymously by the auth server during PAR in public mode;
    # unused (but harmless) in loopback mode.
    return Response.json(
        {
            "client_id": _client_id(datasette, request),
            "client_name": "Datasette",
            "client_uri": _public_origin(datasette, request),
            "redirect_uris": [_redirect_uri(datasette, request)],
            "scope": "atproto",
            "grant_types": ["authorization_code"],
            "response_types": ["code"],
            "token_endpoint_auth_method": "none",
            "application_type": "web",
            "dpop_bound_access_tokens": True,
        }
    )


@provider_gate("bluesky")
async def start(datasette: Datasette, request: Request) -> Response:
    # Identity resolution (handle -> DID -> PDS -> auth server), PAR with a
    # fresh PKCE/DPoP pair, and the flow-row insert land in ticket 03.
    return Response.text("not implemented", status=501)


@provider_gate("bluesky")
async def callback(datasette: Datasette, request: Request) -> Response:
    # Token exchange, the iss/sub authoritative cross-check, and finish_login
    # land in ticket 04.
    return Response.text("not implemented", status=501)


@hookimpl
def startup(datasette: Datasette):
    # A loose plugins_dir module can't append a row to core's
    # internal_migrations.py, so the flow table is created idempotently here
    # instead — CREATE TABLE IF NOT EXISTS is safe on every boot.
    async def inner():
        internal = datasette.get_internal_database()
        await internal.execute_write(_CREATE_FLOW_TABLE)

    return inner


@hookimpl
def register_routes():
    # The provider owns its URL surface under /-/bluesky-auth/... (design
    # D3b). start/callback are wrapped in @provider_gate("bluesky"), so a
    # disabled provider 404s on all three; client_metadata is gated the same
    # way even though it only ever answers GET (no flow can be mid-flight
    # while the provider is disabled).
    return [
        (r"/-/bluesky-auth/start$", start),
        (r"/-/bluesky-auth/callback$", callback),
        (r"/-/bluesky-auth/client-metadata\.json$", client_metadata),
    ]


@hookimpl
def datasette_accounts_auth_providers(datasette: Datasette) -> list[AuthProvider]:
    return [BlueskyProvider()]
