"""JWT + API-key authentication with role-based access control."""

import hashlib
import secrets
from datetime import datetime, timedelta, timezone

import bcrypt
from fastapi import Depends, HTTPException, Request
from fastapi.security import APIKeyHeader, HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from pydantic import BaseModel

from backend.config import get_settings

# ── Password hashing ───────────────────────────────────────────────────


def hash_password(plain: str) -> str:
    """Hash a plaintext password with bcrypt."""
    return bcrypt.hashpw(plain.encode(), bcrypt.gensalt()).decode()


def verify_password(plain: str, hashed: str) -> bool:
    """Verify a plaintext password against a bcrypt hash."""
    return bcrypt.checkpw(plain.encode(), hashed.encode())


# ── JWT tokens ─────────────────────────────────────────────────────────


def create_access_token(user_id: int, email: str, role: str) -> str:
    """Create a short-lived JWT access token."""
    settings = get_settings()
    expire = datetime.now(timezone.utc) + timedelta(minutes=settings.jwt_access_expire_minutes)
    payload = {
        "sub": str(user_id),
        "email": email,
        "role": role,
        "exp": expire,
        "iat": datetime.now(timezone.utc),
    }
    return jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)


def decode_access_token(token: str) -> dict:
    """Decode and validate a JWT access token. Raises JWTError on failure."""
    settings = get_settings()
    return jwt.decode(token, settings.jwt_secret, algorithms=[settings.jwt_algorithm])


# ── Refresh tokens ─────────────────────────────────────────────────────


def create_refresh_token() -> str:
    """Generate a cryptographically random refresh token."""
    return secrets.token_hex(64)


def hash_refresh_token(token: str) -> str:
    """SHA-256 hash a refresh token for secure DB storage."""
    return hashlib.sha256(token.encode()).hexdigest()


# ── Current user model ─────────────────────────────────────────────────


class CurrentUser(BaseModel):
    """Represents the authenticated user for dependency injection."""

    id: int
    email: str
    username: str
    role: str  # "admin" or "analyst"


# ── FastAPI security schemes ───────────────────────────────────────────

bearer_scheme = HTTPBearer(auto_error=False)
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

# Synthetic admin user for backward-compatible modes (API key / no auth)
_SYNTHETIC_ADMIN = CurrentUser(id=0, email="api-key@system", username="API Key", role="admin")


async def get_current_user(
    request: Request,
    bearer: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
    api_key: str | None = Depends(api_key_header),
) -> CurrentUser:
    """Resolve the current user via triple fallback:

    1. Authorization: Bearer <JWT> → decode token, return user
    2. X-API-Key header → match against configured API_KEY, return synthetic admin
    3. No auth configured (jwt_secret + api_key both empty) → return synthetic admin
    4. Otherwise → 401
    """
    settings = get_settings()

    # Strategy 1: JWT Bearer token
    if bearer and bearer.credentials:
        if not settings.jwt_secret:
            raise HTTPException(
                status_code=401,
                detail="JWT authentication is not configured",
            )
        try:
            payload = decode_access_token(bearer.credentials)
            user = CurrentUser(
                id=int(payload["sub"]),
                email=payload["email"],
                username=payload.get("username", payload["email"]),
                role=payload["role"],
            )
            # Store user_id on request.state for per-user rate limiting
            request.state.user_id = user.id
            return user
        except (JWTError, KeyError, ValueError) as exc:
            raise HTTPException(
                status_code=401,
                detail=f"Invalid or expired token: {exc}",
            ) from exc

    # Strategy 2: Legacy API key
    if api_key:
        if settings.api_key and api_key == settings.api_key:
            request.state.user_id = 0
            return _SYNTHETIC_ADMIN
        raise HTTPException(status_code=401, detail="Invalid API key")

    # Strategy 3: No auth configured at all → backward-compatible open access
    if not settings.jwt_secret and not settings.api_key:
        request.state.user_id = 0
        return _SYNTHETIC_ADMIN

    raise HTTPException(status_code=401, detail="Authentication required")


def require_role(required_role: str):
    """Return a dependency that enforces a minimum role.

    Admin passes all checks. Analyst only passes if required_role == 'analyst'.
    """

    async def _check_role(
        current_user: CurrentUser = Depends(get_current_user),
    ) -> CurrentUser:
        if current_user.role == "admin":
            return current_user
        if current_user.role != required_role:
            raise HTTPException(
                status_code=403,
                detail=f"Requires '{required_role}' role",
            )
        return current_user

    return _check_role
