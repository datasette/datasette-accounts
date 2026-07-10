"""Pydantic contracts: page-data (initial render) + API request/response models."""

from typing import List, Optional

from pydantic import BaseModel


# --------------------------------------------------------------------------
# Page data (embedded in the HTML shell as #pageData)
# --------------------------------------------------------------------------


class LoginPageData(BaseModel):
    next: str = "/"
    # Optional admin-authored help/contact note (plain text), "" when unset.
    help: str = ""
    # True while self-registration is open (the runtime DB toggle) — shows the
    # "Request an account" link under the form. See plans/self-registration.
    allow_register: bool = False


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
    # Current state of the runtime self-registration toggle, so the header
    # switch renders with the live value. See plans/self-registration.
    registration_enabled: bool = False


class OwnSessionRow(BaseModel):
    token_sha256: str
    created_at: str
    expires_at: str
    last_seen_at: str
    user_agent: Optional[str] = None
    ip: Optional[str] = None
    # True for the session the viewer is currently browsing with (computed
    # server-side by comparing token_sha256 against the request's own cookie).
    current: bool = False


class AccountPageData(BaseModel):
    id: str
    username: str
    is_admin: bool
    must_change_password: bool
    # Omitted (stays []) during the forced-password-change state — the account
    # page renders password-only until the account is in its normal state.
    sessions: List[OwnSessionRow] = []


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


class MessagesPageData(BaseModel):
    slots: List[SiteMessageSlot]


# --- Login attempts (admin audit view) ---


class LoginAttemptRow(BaseModel):
    id: int
    username: Optional[str] = None
    ip: Optional[str] = None
    timestamp: str
    # 1 on a successful sign-in, 0 otherwise.
    success: int
    # Why the attempt landed where it did: success / bad_password / no_such_user
    # / disabled / expired / locked / no_password / reauth. NULL on rows written
    # before this was tracked.
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


__exports__ = [
    LoginPageData,
    RegisterPageData,
    AdminPageData,
    AccountPageData,
    CapabilitiesPageData,
    MessagesPageData,
    LoginAttemptsPageData,
    SetPasswordPageData,
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


class SessionRow(BaseModel):
    token_sha256: str
    created_at: str
    expires_at: str
    last_seen_at: str
    user_agent: Optional[str] = None
    ip: Optional[str] = None


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
