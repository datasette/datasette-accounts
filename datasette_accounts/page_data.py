"""Pydantic contracts: page-data (initial render) + API request/response models."""

from typing import List, Optional

from pydantic import BaseModel


# --------------------------------------------------------------------------
# Page data (embedded in the HTML shell as #pageData)
# --------------------------------------------------------------------------


class IdentityRow(BaseModel):
    # One external sign-in identity linked to an account (design §6). `subject`
    # is the IdP's stable id (never an email); `label` is the provider's display
    # label resolved from the live registry (falls back to the provider key when
    # the provider package is no longer installed).
    provider: str
    label: str
    subject: str
    created_at: str
    last_login_at: Optional[str] = None


class ProviderButton(BaseModel):
    # One enabled external sign-in provider, rendered on the login page as a
    # "Continue with {label}" button (design §9). `start_url` is a full-page
    # navigation target (the redirect-based flow's entry), already carrying the
    # page's validated `next`. Descriptors only (D10) — the optional branding
    # below is declarative data from the descriptor, not provider-owned HTML.
    key: str
    label: str
    start_url: str
    # Inline <svg> element (startup-validated shape), rendered inside the
    # button; None → text-only button.
    icon: Optional[str] = None
    # Hex colour (startup-validated) for the button background (white text);
    # None → the neutral default button style.
    brand_color: Optional[str] = None


class LoginPageData(BaseModel):
    next: str = "/"
    # Optional admin-authored help/contact note (plain text), "" when unset.
    help: str = ""
    # True while self-registration is open (the runtime DB toggle) — shows the
    # "Request an account" link under the form. See plans/self-registration.
    allow_register: bool = False
    # True while the built-in password provider is enabled (the runtime DB
    # toggle). When false, the page renders no username/password form — see
    # plans/auth-providers. Enabled by default (absent settings row).
    password_enabled: bool = True
    # Enabled external providers, in registry order — the "Continue with …"
    # buttons below the form (or the whole page when password is disabled).
    providers: List[ProviderButton] = []


class RegisterPageData(BaseModel):
    # Optional admin-authored help/contact note, rendered like login_help.
    help: str = ""


class UserRow(BaseModel):
    id: str
    username: str
    is_admin: bool
    disabled: bool
    must_change_password: bool
    locked: bool
    # True while the account holds a live invite link (no password chosen yet).
    # Derived from the password-tokens table, not a users column.
    invited: bool
    # True when the invite link lapsed unused — the account still has no usable
    # password and needs a re-mint (mutually exclusive with `invited`).
    invite_expired: bool
    # Metadata for the account's one-time link, at most one per account:
    # "invite" (live or lapsed) or "reset" (live only — expired reset links are
    # meaningless and hidden). All None when the account has no link. The URL
    # itself is never recoverable — only its hash is stored.
    link_purpose: Optional[str] = None
    link_expires_at: Optional[str] = None
    # Minting admin's username, falling back to the raw actor id for synthetic
    # actors ("root", "cli:$USER") or a since-deleted account.
    link_created_by: Optional[str] = None
    # External sign-in identities linked to this account (empty for a
    # password-only account). Populated on the admin surfaces (design §6) so an
    # admin can see and unlink an account's SSO methods.
    identities: List[IdentityRow] = []
    created_at: str
    # None until the first successful sign-in — the account is still "pending".
    last_login_at: Optional[str] = None
    # None = never expires. Set/clear is a later ticket; this ticket only reads
    # + enforces it (like `locked`, computed lexicographically against "now").
    expires_at: Optional[str] = None
    expired: bool
    # True for a self-registered account awaiting an admin's approve/reject
    # (see plans/self-registration). Distinct from `disabled` — no verdict yet.
    pending_approval: bool


class AdminPageData(BaseModel):
    users: List[UserRow]
    # The viewing admin's own account id, so the table can mark their row
    # with a "(you)" label.
    viewer_id: str


class OwnSessionRow(BaseModel):
    token_sha256: str
    created_at: str
    expires_at: str
    last_seen_at: str
    user_agent: Optional[str] = None
    ip: Optional[str] = None
    # Which sign-in provider minted this session (provenance, design §7):
    # "password" for the built-in flow, else the external provider's key.
    # Rendered as a small "Signed in via" badge in the sessions table.
    provider: str = "password"
    # True for the session the viewer is currently browsing with (computed
    # server-side by comparing token_sha256 against the request's own cookie).
    current: bool = False


class LinkableProvider(BaseModel):
    # An enabled external provider the account has NOT yet linked — offered as a
    # "Link…" button in the account's Sign-in methods section (design §6). Both
    # the key (sent to the link-start API) and the display label are carried so
    # the button can read "Link Okta…" without a second registry round-trip.
    key: str
    label: str


class AccountPageData(BaseModel):
    id: str
    username: str
    is_admin: bool
    must_change_password: bool
    # Omitted (stays []) during the forced-password-change state — the account
    # page renders password-only until the account is in its normal state.
    sessions: List[OwnSessionRow] = []
    # The account's linked external sign-in methods (design §6, "Sign-in
    # methods"). Empty for a password-only account or during forced change.
    identities: List[IdentityRow] = []
    # Enabled external providers this account has NOT yet linked — the "Link…"
    # buttons to offer ({key, label}). Empty during forced change.
    linkable_providers: List[LinkableProvider] = []
    # False when the account has no usable password (SSO-only). Drives whether
    # linking asks for a password (step-up) or names an already-linked provider.
    has_password: bool = True


# --- Capabilities (F1) ---


class CapabilityGrant(BaseModel):
    id: int
    action: str
    principal_type: str
    actor_id: Optional[str] = None
    group_id: Optional[int] = None
    created_at: str
    created_by: Optional[str] = None
    # Resolved display labels (NULL if the account/group no longer exists).
    actor_username: Optional[str] = None
    group_name: Optional[str] = None


class ConfigGrant(BaseModel):
    # Read-only view of a datasette.yaml grant that applies to an action (D8).
    source: str
    allow_json: str


class GrantableAction(BaseModel):
    name: str
    description: str = ""
    also_requires: Optional[str] = None
    # Required (always populated by the server) so the generated TS types are
    # non-optional and can be indexed without undefined guards.
    grants: List[CapabilityGrant]
    # Principal kinds an admin may target for this action (D11).
    offerable_principals: List[str]
    config_grants: List[ConfigGrant]


class GroupOption(BaseModel):
    id: int
    name: str


class CapabilitiesPageData(BaseModel):
    actions: List[GrantableAction]
    groups: List[GroupOption]
    has_acl: bool


# --- Site messages (admin-editable help text) ---


class SiteMessageSlot(BaseModel):
    key: str
    label: str
    description: str
    # Current stored body, "" when the slot is unset.
    body: str = ""


class ProviderAdminRow(BaseModel):
    # One installed sign-in provider, as shown in the Configuration page's
    # "Sign-in providers" section (design §9). See plans/auth-providers.
    key: str
    label: str
    # Provider package name — the top-level package of the provider class's
    # module (e.g. "datasette_accounts" for the built-in password provider).
    source: str
    # True for the built-in password provider (key == "password").
    builtin: bool
    # Runtime enabled bit (design §7): password defaults enabled, external
    # providers default disabled until an admin flips them on.
    enabled: bool
    # Deployment state: is the provider ready to authenticate (credentials/config
    # present)? Distinct from `enabled` — an admin may pre-enable before deploying
    # creds. False here → the login button + link targets hide it, and the admin
    # table shows a "not configured" warning chip. Default True (most providers
    # need no external config). See plans/auth-providers, AuthProvider.configured.
    configured: bool = True
    # Signups policy: "off" | "approval" | "auto".
    signups: str
    # Count of external identities linked through this provider (0 for password,
    # which has no identities rows — D4).
    linked_count: int


class ConfigPageData(BaseModel):
    """The /-/admin/config page: site messages + self-registration + providers."""

    slots: List[SiteMessageSlot]
    # Current state of the runtime self-registration toggle, so the switch
    # renders with the live value. See plans/self-registration.
    registration_enabled: bool = False
    # One row per installed sign-in provider, for the "Sign-in providers"
    # section (design §9). See plans/auth-providers.
    providers: List[ProviderAdminRow] = []


# --- Login attempts (admin audit view) ---


class LoginAttemptRow(BaseModel):
    id: int
    username: Optional[str] = None
    ip: Optional[str] = None
    timestamp: str
    # 1 on a successful sign-in, 0 otherwise.
    success: int
    # Why the attempt landed where it did: success / bad_password / no_such_user
    # / disabled / expired / locked / no_password / reauth / register, plus the
    # external-provider reasons provider_no_account / provider_pending /
    # provider_disabled / provider_expired (see plans/auth-providers). NULL on
    # rows written before this was tracked.
    reason: Optional[str] = None


class LoginAttemptsPageData(BaseModel):
    attempts: List[LoginAttemptRow]
    # Initial filters (from the ?username=/?ip= query string), echoed so the page
    # shows them pre-populated; "" means no filter.
    filter_username: str = ""
    filter_ip: str = ""


# --- Set-password page (invite / reset links) ---


class SetPasswordPageData(BaseModel):
    # False for a missing/invalid/expired/already-used token — the page then
    # shows one generic error, never distinguishing the reason.
    valid: bool
    # "invite" or "reset"; "" when invalid.
    purpose: str = ""
    username: str = ""
    # The raw token, echoed back so the completion POST can send it; "" when
    # invalid.
    token: str = ""


# --- Admin audit trail (accountability sibling of the login-attempts view) ---


class AdminAuditRow(BaseModel):
    id: int
    timestamp: str
    operation: str
    # The ids stay in the payload so the UI can fall back to them when a
    # username subselect returned NULL (deleted account) or the actor is
    # synthetic (root, cli:$USER).
    actor_id: Optional[str] = None
    actor_username: Optional[str] = None
    target_id: Optional[str] = None
    target_username: Optional[str] = None
    # JSON detail written with the row; NULL for operations without extras.
    detail: Optional[str] = None


class AdminAuditPageData(BaseModel):
    entries: List[AdminAuditRow]
    # Distinct operation names present in the trail, for the filter dropdown.
    operations: List[str]
    # Initial filters (from the ?username=/?operation= query string), echoed so
    # the page shows them pre-populated; "" means no filter.
    filter_username: str = ""
    filter_operation: str = ""


__exports__ = [
    LoginPageData,
    RegisterPageData,
    AdminPageData,
    AccountPageData,
    CapabilitiesPageData,
    ConfigPageData,
    LoginAttemptsPageData,
    SetPasswordPageData,
    AdminAuditPageData,
]


# --------------------------------------------------------------------------
# API request / response models
# --------------------------------------------------------------------------


class AuthenticateRequest(BaseModel):
    username: str
    password: str
    next: Optional[str] = None


class AuthenticateResponse(BaseModel):
    ok: bool
    redirect: Optional[str] = None
    must_change_password: Optional[bool] = None
    error: Optional[str] = None


class OkResponse(BaseModel):
    ok: bool
    error: Optional[str] = None


class ChangePasswordRequest(BaseModel):
    # Optional: not required in the first-login forced-change flow, where the
    # session already proves the current (temp) password was just entered.
    current_password: Optional[str] = None
    new_password: str


class CreateUserRequest(BaseModel):
    username: str
    # Omit `password` (or send generate=True) to have the server mint a strong
    # random password and return it once in the response.
    password: Optional[str] = None
    generate: bool = False
    is_admin: bool = False
    must_change_password: bool = True


class CreateUserResponse(BaseModel):
    ok: bool
    id: Optional[str] = None
    # Present only when the password was server-generated (shown once).
    password: Optional[str] = None
    error: Optional[str] = None


class TargetRequest(BaseModel):
    """Admin operations that act on a single user id."""

    id: str


class ResetPasswordRequest(BaseModel):
    id: str
    # Omit `password` (or send generate=True) to mint a strong random password
    # and return it once in the response.
    password: Optional[str] = None
    generate: bool = False


class ResetPasswordResponse(BaseModel):
    ok: bool
    # Present only when the password was server-generated (shown once).
    password: Optional[str] = None
    error: Optional[str] = None


class SetExpiryRequest(BaseModel):
    id: str
    # At most one of the two; both omitted clears the deadline. `expires_at`
    # is an ISO-ish timestamp parsed/normalized in SQL; `in_days` is a
    # positive relative deadline computed in SQL.
    expires_at: Optional[str] = None
    in_days: Optional[int] = None


class RevokeSessionRequest(BaseModel):
    id: str
    token_sha256: str


class RevokeOwnSessionRequest(BaseModel):
    """Self-service revocation: no user id — always scoped to the caller."""

    token_sha256: str


class SessionRow(BaseModel):
    token_sha256: str
    created_at: str
    expires_at: str
    last_seen_at: str
    user_agent: Optional[str] = None
    ip: Optional[str] = None
    # Which sign-in provider minted this session (provenance, design §7);
    # "password" for the built-in flow, else the external provider's key.
    provider: str = "password"


class SessionListResponse(BaseModel):
    ok: bool
    sessions: List[SessionRow] = []


class GrantCapabilityRequest(BaseModel):
    action: str
    principal_type: str  # actor | group | everyone | authenticated | anonymous
    actor_id: Optional[str] = None
    group_id: Optional[int] = None


class RevokeCapabilityRequest(BaseModel):
    id: int


class SetSiteMessageRequest(BaseModel):
    key: str
    # Blank clears the slot.
    body: str = ""


class LoginAttemptsRequest(BaseModel):
    # Exact-match filters; "" / omitted means unfiltered.
    username: str = ""
    ip: str = ""


# --- Invite / reset links (see plans/invite-links) ---


class CompleteSetPasswordRequest(BaseModel):
    token: str
    new_password: str


class InviteRequest(BaseModel):
    username: str
    is_admin: bool = False


class InviteResponse(BaseModel):
    ok: bool
    id: Optional[str] = None
    # The absolute one-time set-password URL, shown once.
    url: Optional[str] = None
    error: Optional[str] = None


class ResetLinkResponse(BaseModel):
    ok: bool
    # The absolute one-time set-password URL, shown once.
    url: Optional[str] = None
    error: Optional[str] = None


# --- Self-registration (see plans/self-registration) ---


class RegisterRequest(BaseModel):
    username: str
    password: str


class SetRegistrationRequest(BaseModel):
    enabled: bool


class SetProviderRequest(BaseModel):
    # Admin toggle for one sign-in provider (design §9). `key` must be in the
    # registry. Either or both of the two fields may be sent; each `None` field
    # is left unchanged.
    key: str
    enabled: Optional[bool] = None
    signups: Optional[str] = None  # "off" | "approval" | "auto"


# --- Identity linking / unlinking (see plans/auth-providers §6) ---


class LinkStartRequest(BaseModel):
    # Target external provider to link to the signed-in account.
    provider: str
    # Step-up proof for a password account: the account's current password.
    password: Optional[str] = None
    # Step-up proof for a password-less account: the key of an already-linked
    # provider whose flow the user re-completes.
    step_up_provider: Optional[str] = None


class LinkStartResponse(BaseModel):
    ok: bool
    # The URL to send the browser to next: the target provider's start (direct
    # password link) or the step-up provider's start (password-less). Present
    # only on success.
    start_url: Optional[str] = None
    error: Optional[str] = None


class UnlinkRequest(BaseModel):
    # The (provider, subject) to unlink from the signed-in account.
    provider: str
    subject: str


class AdminUnlinkRequest(BaseModel):
    # Same as UnlinkRequest plus the account whose identity is being unlinked.
    target_id: str
    provider: str
    subject: str


class AdminAuditRequest(BaseModel):
    # Exact-match filters; "" / omitted means unfiltered. `username` is the
    # target's username, resolved server-side to a target id (unknown → empty
    # result, not an error).
    username: str = ""
    operation: str = ""
