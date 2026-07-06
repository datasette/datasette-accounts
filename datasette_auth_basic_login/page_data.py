"""Pydantic contracts: page-data (initial render) + API request/response models."""

from typing import List, Optional

from pydantic import BaseModel


# --------------------------------------------------------------------------
# Page data (embedded in the HTML shell as #pageData)
# --------------------------------------------------------------------------


class LoginPageData(BaseModel):
    next: str = "/"


class UserRow(BaseModel):
    id: str
    username: str
    is_admin: bool
    disabled: bool
    must_change_password: bool
    locked: bool
    created_at: str


class AdminPageData(BaseModel):
    users: List[UserRow]


class AccountPageData(BaseModel):
    id: str
    username: str
    is_admin: bool
    must_change_password: bool


__exports__ = [LoginPageData, AdminPageData, AccountPageData]


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
    current_password: str
    new_password: str


class CreateUserRequest(BaseModel):
    username: str
    password: str
    is_admin: bool = False
    must_change_password: bool = True


class CreateUserResponse(BaseModel):
    ok: bool
    id: Optional[str] = None
    error: Optional[str] = None


class TargetRequest(BaseModel):
    """Admin operations that act on a single user id."""

    id: str


class ResetPasswordRequest(BaseModel):
    id: str
    password: str


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
