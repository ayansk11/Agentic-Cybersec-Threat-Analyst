"""Authentication API endpoints: register, login, OAuth, token refresh."""

import logging
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Cookie, Depends, HTTPException, Response
from fastapi.responses import RedirectResponse

from backend.api.auth import (
    CurrentUser,
    create_access_token,
    create_refresh_token,
    get_current_user,
    hash_password,
    hash_refresh_token,
    verify_password,
)
from backend.api.oauth import generate_state, get_oauth_provider
from backend.api.schemas import (
    AuthProvidersResponse,
    AuthResponse,
    LoginRequest,
    PasswordResetConfirm,
    PasswordResetRequest,
    RegisterRequest,
    ResendVerificationRequest,
    UserResponse,
    UserUpdateRequest,
    UsersListResponse,
    VerifyEmailRequest,
    WebhookSettingsResponse,
    WebhookSettingsUpdate,
    WebhookTestRequest,
)
from backend.config import get_settings
from backend.db_users import (
    consume_password_reset_token,
    consume_verification_token,
    count_users,
    create_user,
    get_user_by_email,
    get_user_by_id,
    get_user_by_oauth,
    list_users,
    revoke_all_user_tokens,
    revoke_refresh_token,
    store_password_reset_token,
    store_refresh_token,
    store_verification_token,
    update_user,
    verify_email_token,
    verify_password_reset_token,
    verify_refresh_token,
)

logger = logging.getLogger("backend.auth")

auth_router = APIRouter(prefix="/api/auth", tags=["auth"])


# ── Helpers ─────────────────────────────────────────────────────────────


def _user_to_response(user: dict) -> UserResponse:
    """Convert a DB user dict to a UserResponse."""
    return UserResponse(
        id=user["id"],
        email=user["email"],
        username=user["username"],
        role=user["role"],
        oauth_provider=user.get("oauth_provider"),
        is_active=bool(user.get("is_active", 1)),
        email_verified=bool(user.get("email_verified", 0)),
        created_at=user["created_at"],
    )


async def _issue_tokens(user: dict, response: Response) -> AuthResponse:
    """Create access + refresh tokens and set the refresh cookie."""
    settings = get_settings()
    access_token = create_access_token(user["id"], user["email"], user["role"])
    refresh = create_refresh_token()

    # Store hashed refresh token in DB
    expires_at = (
        datetime.now(timezone.utc) + timedelta(days=settings.jwt_refresh_expire_days)
    ).isoformat()
    await store_refresh_token(user["id"], hash_refresh_token(refresh), expires_at)

    # Set refresh token as HTTP-only cookie
    response.set_cookie(
        key="refresh_token",
        value=refresh,
        httponly=True,
        samesite="lax",
        secure=settings.cookie_secure,
        max_age=settings.jwt_refresh_expire_days * 86400,
        path="/api/auth",
    )

    return AuthResponse(
        access_token=access_token,
        user=_user_to_response(user),
    )


async def _send_verification_token(user_id: int, email: str) -> str:
    """Generate a verification token and send it via email (or log if SMTP not configured)."""
    from backend.mailer import send_verification_email

    token = create_refresh_token()  # reuse random token generator
    token_hash_val = hash_refresh_token(token)
    expires_at = (datetime.now(timezone.utc) + timedelta(hours=24)).isoformat()
    await store_verification_token(user_id, token_hash_val, expires_at)

    settings = get_settings()
    await send_verification_email(email, token, settings.frontend_url)
    return token


async def _send_reset_token(user_id: int, email: str) -> str:
    """Generate a reset token and send it via email (or log if SMTP not configured)."""
    from backend.mailer import send_password_reset_email

    token = create_refresh_token()
    token_hash_val = hash_refresh_token(token)
    expires_at = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
    await store_password_reset_token(user_id, token_hash_val, expires_at)

    settings = get_settings()
    await send_password_reset_email(email, token, settings.frontend_url)
    return token


# ── Registration ────────────────────────────────────────────────────────


@auth_router.post("/register", response_model=AuthResponse)
async def register(body: RegisterRequest, response: Response):
    """Register a new user with email and password."""
    settings = get_settings()
    if not settings.jwt_secret:
        raise HTTPException(status_code=400, detail="JWT authentication is not configured")

    existing = await get_user_by_email(body.email)
    if existing:
        raise HTTPException(status_code=409, detail="Email already registered")

    user_id = await create_user(
        email=body.email,
        username=body.username,
        hashed_password=hash_password(body.password),
        role="analyst",
    )
    user = await get_user_by_id(user_id)
    logger.info("New user registered: %s (id=%d)", body.email, user_id)

    # Generate email verification token
    await _send_verification_token(user_id, body.email)

    return await _issue_tokens(user, response)


# ── Login ───────────────────────────────────────────────────────────────


@auth_router.post("/login", response_model=AuthResponse)
async def login(body: LoginRequest, response: Response):
    """Authenticate with email and password."""
    settings = get_settings()
    if not settings.jwt_secret:
        raise HTTPException(status_code=400, detail="JWT authentication is not configured")

    user = await get_user_by_email(body.email)
    if not user or not user.get("hashed_password"):
        raise HTTPException(status_code=401, detail="Invalid email or password")

    if not verify_password(body.password, user["hashed_password"]):
        raise HTTPException(status_code=401, detail="Invalid email or password")

    if not user.get("is_active", 1):
        raise HTTPException(status_code=403, detail="Account is disabled")

    logger.info("User logged in: %s", body.email)
    return await _issue_tokens(user, response)


# ── Token refresh ───────────────────────────────────────────────────────


@auth_router.post("/refresh")
async def refresh(
    response: Response,
    refresh_token: str | None = Cookie(default=None),
):
    """Rotate refresh token and issue a new access token."""
    if not refresh_token:
        raise HTTPException(status_code=401, detail="No refresh token provided")

    token_hash = hash_refresh_token(refresh_token)
    token_row = await verify_refresh_token(token_hash)
    if not token_row:
        raise HTTPException(status_code=401, detail="Invalid or expired refresh token")

    # Revoke old token (rotation)
    await revoke_refresh_token(token_hash)

    user = await get_user_by_id(token_row["user_id"])
    if not user or not user.get("is_active", 1):
        raise HTTPException(status_code=401, detail="User account not found or disabled")

    return await _issue_tokens(user, response)


# ── Logout ──────────────────────────────────────────────────────────────


@auth_router.post("/logout")
async def logout(
    response: Response,
    refresh_token: str | None = Cookie(default=None),
):
    """Revoke refresh token and clear cookie."""
    if refresh_token:
        await revoke_refresh_token(hash_refresh_token(refresh_token))

    response.delete_cookie(key="refresh_token", path="/api/auth")
    return {"message": "Logged out"}


# ── Current user profile ───────────────────────────────────────────────


@auth_router.get("/me", response_model=UserResponse)
async def get_me(current_user: CurrentUser = Depends(get_current_user)):
    """Return the current authenticated user's profile."""
    if current_user.id == 0:
        # Synthetic user from API key / no-auth mode
        return UserResponse(
            id=0,
            email=current_user.email,
            username=current_user.username,
            role=current_user.role,
            email_verified=True,
            created_at=datetime.now(timezone.utc).isoformat(),
        )
    user = await get_user_by_id(current_user.id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return _user_to_response(user)


# ── OAuth2 ──────────────────────────────────────────────────────────────


@auth_router.get("/oauth/{provider}/login")
async def oauth_login(provider: str, response: Response):
    """Redirect to OAuth provider's authorization page."""
    settings = get_settings()
    if not settings.jwt_secret:
        raise HTTPException(status_code=400, detail="JWT authentication is not configured")

    oauth = get_oauth_provider(provider)
    if not oauth.is_configured:
        raise HTTPException(
            status_code=400,
            detail=f"{provider.title()} OAuth is not configured",
        )

    state = generate_state()
    # Store state in a cookie for CSRF validation on callback
    authorize_url = oauth.get_authorize_url(state)

    redirect = RedirectResponse(url=authorize_url, status_code=302)
    redirect.set_cookie(
        key="oauth_state",
        value=state,
        httponly=True,
        samesite="lax",
        max_age=600,  # 10 minutes
        path="/api/auth",
    )
    return redirect


@auth_router.get("/oauth/{provider}/callback")
async def oauth_callback(
    provider: str,
    code: str,
    state: str,
    response: Response,
    oauth_state: str | None = Cookie(default=None),
):
    """Handle OAuth callback: exchange code, create/link user, redirect to frontend."""
    settings = get_settings()

    # CSRF validation
    if not oauth_state or oauth_state != state:
        raise HTTPException(status_code=400, detail="Invalid OAuth state parameter")

    oauth = get_oauth_provider(provider)

    try:
        # Exchange code for provider access token
        token_data = await oauth.exchange_code(code)
        provider_token = token_data.get("access_token")
        if not provider_token:
            raise HTTPException(
                status_code=400, detail="Failed to obtain access token from provider"
            )

        # Fetch user info from provider
        user_info = await oauth.get_user_info(provider_token)
    except Exception as exc:
        logger.error("OAuth callback failed for %s: %s", provider, exc)
        raise HTTPException(status_code=400, detail=f"OAuth authentication failed: {exc}") from exc

    # Find or create user
    user = await get_user_by_oauth(user_info.provider, user_info.oauth_id)
    if not user:
        # Check if email is already registered (link accounts)
        user = await get_user_by_email(user_info.email)
        if user:
            # Link OAuth to existing email account
            await update_user(
                user["id"],
                oauth_provider=user_info.provider,
                oauth_id=user_info.oauth_id,
            )
            user = await get_user_by_id(user["id"])
        else:
            # Create new user
            user_id = await create_user(
                email=user_info.email,
                username=user_info.username,
                role="analyst",
                oauth_provider=user_info.provider,
                oauth_id=user_info.oauth_id,
            )
            user = await get_user_by_id(user_id)
            logger.info("New OAuth user created: %s via %s", user_info.email, provider)

    if not user.get("is_active", 1):
        raise HTTPException(status_code=403, detail="Account is disabled")

    # Issue tokens
    access_token = create_access_token(user["id"], user["email"], user["role"])
    refresh = create_refresh_token()
    expires_at = (
        datetime.now(timezone.utc) + timedelta(days=settings.jwt_refresh_expire_days)
    ).isoformat()
    await store_refresh_token(user["id"], hash_refresh_token(refresh), expires_at)

    # Redirect to frontend with access token
    redirect = RedirectResponse(
        url=f"{settings.frontend_url}/auth/callback?access_token={access_token}",
        status_code=302,
    )
    redirect.set_cookie(
        key="refresh_token",
        value=refresh,
        httponly=True,
        samesite="lax",
        secure=settings.cookie_secure,
        max_age=settings.jwt_refresh_expire_days * 86400,
        path="/api/auth",
    )
    redirect.delete_cookie(key="oauth_state", path="/api/auth")
    return redirect


# ── Admin: User management ──────────────────────────────────────────────


@auth_router.get("/admin/users", response_model=UsersListResponse)
async def admin_list_users(
    limit: int = 50,
    offset: int = 0,
    current_user: CurrentUser = Depends(get_current_user),
):
    """List all users (admin only)."""
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")

    users = await list_users(limit=limit, offset=offset)
    total = await count_users()
    return UsersListResponse(
        users=[_user_to_response(u) for u in users],
        count=total,
    )


@auth_router.patch("/admin/users/{user_id}", response_model=UserResponse)
async def admin_update_user(
    user_id: int,
    body: UserUpdateRequest,
    current_user: CurrentUser = Depends(get_current_user),
):
    """Update a user's role or active status (admin only)."""
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")

    user = await get_user_by_id(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    updates = {}
    if body.role is not None:
        if body.role not in ("admin", "analyst"):
            raise HTTPException(status_code=400, detail="Role must be 'admin' or 'analyst'")
        updates["role"] = body.role
    if body.is_active is not None:
        updates["is_active"] = 1 if body.is_active else 0
        if not body.is_active:
            # Revoke all tokens when deactivating
            await revoke_all_user_tokens(user_id)

    if updates:
        await update_user(user_id, **updates)
        user = await get_user_by_id(user_id)

    logger.info("Admin updated user %d: %s", user_id, updates)
    return _user_to_response(user)


# ── Password Reset ─────────────────────────────────────────────────────


@auth_router.post("/forgot-password")
async def forgot_password(body: PasswordResetRequest):
    """Request a password reset token. Always returns success to prevent email enumeration."""
    settings = get_settings()
    if not settings.jwt_secret:
        raise HTTPException(status_code=400, detail="JWT authentication is not configured")

    user = await get_user_by_email(body.email)
    if user and user.get("hashed_password"):
        # Only generate token for local accounts (not OAuth-only)
        await _send_reset_token(user["id"], body.email)

    # Always return success to prevent email enumeration
    return {"message": "If an account exists with that email, a reset link has been sent"}


@auth_router.post("/reset-password")
async def reset_password(body: PasswordResetConfirm):
    """Reset password using a valid reset token."""
    token_hash_val = hash_refresh_token(body.token)
    token_row = await verify_password_reset_token(token_hash_val)
    if not token_row:
        raise HTTPException(status_code=400, detail="Invalid or expired reset token")

    user = await get_user_by_id(token_row["user_id"])
    if not user:
        raise HTTPException(status_code=400, detail="User not found")

    # Update password and consume token
    await update_user(user["id"], hashed_password=hash_password(body.new_password))
    await consume_password_reset_token(token_hash_val)
    # Revoke all existing sessions for security
    await revoke_all_user_tokens(user["id"])

    logger.info("Password reset for user: %s", user["email"])
    return {"message": "Password has been reset successfully"}


# ── Email Verification ─────────────────────────────────────────────────


@auth_router.post("/verify-email")
async def verify_email(body: VerifyEmailRequest):
    """Verify a user's email address using a verification token."""
    token_hash_val = hash_refresh_token(body.token)
    token_row = await verify_email_token(token_hash_val)
    if not token_row:
        raise HTTPException(status_code=400, detail="Invalid or expired verification token")

    user = await get_user_by_id(token_row["user_id"])
    if not user:
        raise HTTPException(status_code=400, detail="User not found")

    await update_user(user["id"], email_verified=1)
    await consume_verification_token(token_hash_val)

    logger.info("Email verified for user: %s", user["email"])
    return {"message": "Email verified successfully"}


@auth_router.post("/resend-verification")
async def resend_verification(body: ResendVerificationRequest):
    """Resend a verification email. Always returns success to prevent enumeration."""
    user = await get_user_by_email(body.email)
    if user and not user.get("email_verified", 0):
        await _send_verification_token(user["id"], body.email)

    return {
        "message": "If the email is registered and unverified, a verification link has been sent"
    }


# ── Auth Providers ─────────────────────────────────────────────────────


@auth_router.get("/providers", response_model=AuthProvidersResponse)
async def get_providers():
    """Return which authentication providers are configured."""
    settings = get_settings()
    google_oauth = get_oauth_provider("google")
    github_oauth = get_oauth_provider("github")
    return AuthProvidersResponse(
        local=True,
        google=google_oauth.is_configured,
        github=github_oauth.is_configured,
        jwt_configured=bool(settings.jwt_secret),
    )


# ── Admin: Webhook Settings ───────────────────────────────────────────


@auth_router.get("/admin/settings/webhooks", response_model=WebhookSettingsResponse)
async def get_webhook_settings(
    current_user: CurrentUser = Depends(get_current_user),
):
    """Get current webhook configuration (admin only)."""
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")

    from backend.db_users import get_app_settings_bulk

    settings = get_settings()
    db_settings = await get_app_settings_bulk(["webhook_url", "webhook_severity_threshold"])

    return WebhookSettingsResponse(
        webhook_url=db_settings.get("webhook_url", "") or settings.webhook_url,
        webhook_severity_threshold=(
            db_settings.get("webhook_severity_threshold", "") or settings.webhook_severity_threshold
        ),
        smtp_configured=bool(settings.smtp_host),
    )


@auth_router.put("/admin/settings/webhooks", response_model=WebhookSettingsResponse)
async def update_webhook_settings(
    body: WebhookSettingsUpdate,
    current_user: CurrentUser = Depends(get_current_user),
):
    """Update webhook configuration (admin only). Persisted in DB."""
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")

    from backend.db_users import set_app_setting

    await set_app_setting("webhook_url", body.webhook_url)
    await set_app_setting("webhook_severity_threshold", body.webhook_severity_threshold)

    settings = get_settings()
    logger.info(
        "Admin %s updated webhook settings: url=%s threshold=%s",
        current_user.email,
        body.webhook_url[:30] + "..." if len(body.webhook_url) > 30 else body.webhook_url,
        body.webhook_severity_threshold,
    )

    return WebhookSettingsResponse(
        webhook_url=body.webhook_url,
        webhook_severity_threshold=body.webhook_severity_threshold,
        smtp_configured=bool(settings.smtp_host),
    )


@auth_router.post("/admin/settings/webhooks/test")
async def test_webhook(
    body: WebhookTestRequest,
    current_user: CurrentUser = Depends(get_current_user),
):
    """Send a test webhook payload to the provided URL (admin only)."""
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")

    import httpx

    payload = {
        "event": "test",
        "cve_id": "CVE-0000-0000",
        "severity": "HIGH",
        "summary": "This is a test webhook from ThreatAnalyst.",
        "techniques": [{"id": "T1059", "name": "Command and Scripting Interpreter"}],
    }
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(body.url, json=payload)
        return {"success": True, "status_code": resp.status_code}
    except Exception as exc:
        return {"success": False, "error": str(exc)}
