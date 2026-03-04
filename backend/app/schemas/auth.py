"""Authentication schemas for request/response validation."""

import uuid
from pydantic import BaseModel, EmailStr, Field


class LoginRequest(BaseModel):
    """User login credentials."""

    username: str = Field(..., min_length=3, max_length=100)
    password: str = Field(..., min_length=8)
    totp_code: str | None = Field(None, description="6-digit TOTP code if 2FA is enabled")


class RegisterRequest(BaseModel):
    """New user registration."""

    email: EmailStr
    username: str = Field(..., min_length=3, max_length=100)
    password: str = Field(..., min_length=8)
    full_name: str | None = None


class TokenResponse(BaseModel):
    """JWT token pair response."""

    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int  # seconds


class LoginResponse(BaseModel):
    """Login response — may require 2FA step."""

    access_token: str | None = None
    refresh_token: str | None = None
    token_type: str = "bearer"
    expires_in: int | None = None
    requires_2fa: bool = False
    two_fa_token: str | None = None  # short-lived token for 2FA verification


class RefreshRequest(BaseModel):
    """Token refresh request."""

    refresh_token: str


class UserResponse(BaseModel):
    """Public user information."""

    id: uuid.UUID
    email: str
    username: str
    full_name: str | None
    role: str
    is_active: bool
    totp_enabled: bool = False
    must_change_password: bool = False

    model_config = {"from_attributes": True}


# --- Password Reset ---

class PasswordResetRequest(BaseModel):
    """Request a password reset code via email."""

    email: EmailStr


class PasswordResetConfirm(BaseModel):
    """Confirm password reset with code from email."""

    email: EmailStr
    code: str = Field(..., min_length=6, max_length=8)
    new_password: str = Field(..., min_length=8)


class ChangePasswordRequest(BaseModel):
    """Change password (authenticated user)."""

    current_password: str = Field(..., min_length=8)
    new_password: str = Field(..., min_length=8)


# --- TOTP 2FA ---

class TOTPSetupResponse(BaseModel):
    """TOTP setup information."""

    secret: str
    provisioning_uri: str
    qr_code_base64: str


class TOTPVerifyRequest(BaseModel):
    """Verify a TOTP code to complete setup or authenticate."""

    code: str = Field(..., min_length=6, max_length=6)


class TwoFALoginRequest(BaseModel):
    """Complete login with 2FA code."""

    two_fa_token: str
    totp_code: str = Field(..., min_length=6, max_length=6)
