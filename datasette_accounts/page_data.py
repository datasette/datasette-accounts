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


class UserRow(BaseModel):
    id: str
    username: str
    is_admin: bool
    disabled: bool
    must_change_password: bool
    locked: bool
    created_at: str
    # None until the first successful sign-in — the account is still "pending".
    last_login_at: Optional[str] = None


class AdminPageData(BaseModel):
    users: List[UserRow]


class AccountPageData(BaseModel):
    id: str
    username: str
    is_admin: bool
    must_change_password: bool


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
    # / disabled / locked / reauth. NULL on rows written before this was tracked.
    reason: Optional[str] = None


class LoginAttemptsPageData(BaseModel):
    attempts: List[LoginAttemptRow]
    # Initial filters (from the ?username=/?ip= query string), echoed so the page
    # shows them pre-populated; "" means no filter.
    filter_username: str = ""
    filter_ip: str = ""


__exports__ = [
    LoginPageData,
    AdminPageData,
    AccountPageData,
    CapabilitiesPageData,
    MessagesPageData,
    LoginAttemptsPageData,
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
