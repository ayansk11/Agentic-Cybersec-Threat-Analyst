"""Tests for JWT authentication, registration, login, and token management."""

import pytest
from unittest.mock import patch, MagicMock

from backend.api.auth import (
    CurrentUser,
    create_access_token,
    create_refresh_token,
    decode_access_token,
    hash_password,
    hash_refresh_token,
    verify_password,
)


# ── Password hashing ───────────────────────────────────────────────────


class TestPasswordHashing:
    def test_hash_and_verify(self):
        hashed = hash_password("mysecretpassword")
        assert hashed != "mysecretpassword"
        assert verify_password("mysecretpassword", hashed)

    def test_wrong_password_fails(self):
        hashed = hash_password("correct")
        assert not verify_password("wrong", hashed)

    def test_different_hashes(self):
        h1 = hash_password("same")
        h2 = hash_password("same")
        # bcrypt uses random salts, so hashes differ
        assert h1 != h2


# ── JWT tokens ─────────────────────────────────────────────────────────


class TestJWTTokens:
    @patch("backend.api.auth.get_settings")
    def test_create_and_decode(self, mock_settings):
        settings = MagicMock()
        settings.jwt_secret = "test-secret-key-123"
        settings.jwt_algorithm = "HS256"
        settings.jwt_access_expire_minutes = 15
        mock_settings.return_value = settings

        token = create_access_token(user_id=42, email="user@test.com", role="analyst")
        assert isinstance(token, str)
        assert len(token) > 0

        payload = decode_access_token(token)
        assert payload["sub"] == "42"
        assert payload["email"] == "user@test.com"
        assert payload["role"] == "analyst"
        assert "exp" in payload
        assert "iat" in payload


# ── Refresh tokens ─────────────────────────────────────────────────────


class TestRefreshTokens:
    def test_create_refresh_token_unique(self):
        t1 = create_refresh_token()
        t2 = create_refresh_token()
        assert t1 != t2
        assert len(t1) == 128  # 64 bytes hex = 128 chars

    def test_hash_refresh_token_deterministic(self):
        token = "test-refresh-token"
        h1 = hash_refresh_token(token)
        h2 = hash_refresh_token(token)
        assert h1 == h2
        assert h1 != token


# ── CurrentUser model ──────────────────────────────────────────────────


class TestCurrentUser:
    def test_admin_user(self):
        user = CurrentUser(id=1, email="admin@test.com", username="Admin", role="admin")
        assert user.role == "admin"
        assert user.id == 1

    def test_analyst_user(self):
        user = CurrentUser(id=2, email="analyst@test.com", username="Analyst", role="analyst")
        assert user.role == "analyst"


# ── Legacy auth compatibility ──────────────────────────────────────────


class TestLegacyAuth:
    """Tests that the old API key mechanism still works."""

    def test_health_always_public(self, test_client):
        resp = test_client.get("/api/health")
        assert resp.status_code == 200


# ── Schema validation ──────────────────────────────────────────────────


class TestAuthSchemas:
    def test_register_request_validation(self):
        from backend.api.schemas import RegisterRequest

        req = RegisterRequest(email="a@b.com", username="ab", password="12345678")
        assert req.email == "a@b.com"

    def test_register_request_short_username_fails(self):
        from backend.api.schemas import RegisterRequest

        with pytest.raises(Exception):
            RegisterRequest(email="a@b.com", username="a", password="12345678")

    def test_register_request_short_password_fails(self):
        from backend.api.schemas import RegisterRequest

        with pytest.raises(Exception):
            RegisterRequest(email="a@b.com", username="ab", password="short")

    def test_login_request(self):
        from backend.api.schemas import LoginRequest

        req = LoginRequest(email="a@b.com", password="secret123")
        assert req.email == "a@b.com"

    def test_user_response(self):
        from backend.api.schemas import UserResponse

        resp = UserResponse(
            id=1, email="a@b.com", username="test", role="analyst", created_at="2024-01-01T00:00:00"
        )
        assert resp.role == "analyst"
        assert resp.oauth_provider is None

    def test_auth_response(self):
        from backend.api.schemas import AuthResponse, UserResponse

        user = UserResponse(
            id=1, email="a@b.com", username="test", role="analyst", created_at="2024-01-01T00:00:00"
        )
        resp = AuthResponse(access_token="abc.def.ghi", user=user)
        assert resp.token_type == "bearer"

    def test_user_update_request(self):
        from backend.api.schemas import UserUpdateRequest

        req = UserUpdateRequest(role="admin")
        assert req.role == "admin"
        assert req.is_active is None

    def test_password_reset_request(self):
        from backend.api.schemas import PasswordResetRequest

        req = PasswordResetRequest(email="a@b.com")
        assert req.email == "a@b.com"

    def test_password_reset_confirm_validation(self):
        from backend.api.schemas import PasswordResetConfirm

        req = PasswordResetConfirm(token="abc123", new_password="newpassword123")
        assert req.token == "abc123"
        with pytest.raises(Exception):
            PasswordResetConfirm(token="abc", new_password="short")

    def test_verify_email_request(self):
        from backend.api.schemas import VerifyEmailRequest

        req = VerifyEmailRequest(token="verify-token-123")
        assert req.token == "verify-token-123"

    def test_auth_providers_response(self):
        from backend.api.schemas import AuthProvidersResponse

        resp = AuthProvidersResponse(local=True, google=True, github=False, jwt_configured=True)
        assert resp.google is True
        assert resp.github is False

    def test_user_response_email_verified(self):
        from backend.api.schemas import UserResponse

        resp = UserResponse(
            id=1,
            email="a@b.com",
            username="test",
            role="analyst",
            email_verified=True,
            created_at="2024-01-01T00:00:00",
        )
        assert resp.email_verified is True

    def test_resend_verification_request(self):
        from backend.api.schemas import ResendVerificationRequest

        req = ResendVerificationRequest(email="a@b.com")
        assert req.email == "a@b.com"


# ── API endpoint tests ──────────────────────────────────────────────────


class TestAuthEndpoints:
    def test_providers_endpoint(self, test_client):
        resp = test_client.get("/api/auth/providers")
        assert resp.status_code == 200
        data = resp.json()
        assert "local" in data
        assert "google" in data
        assert "github" in data
        assert "jwt_configured" in data

    @patch("backend.api.auth_routes.get_settings")
    def test_forgot_password_no_jwt_returns_400(self, mock_settings, test_client):
        """Without JWT configured, forgot-password returns 400."""
        settings = MagicMock()
        settings.jwt_secret = ""
        mock_settings.return_value = settings
        resp = test_client.post(
            "/api/auth/forgot-password",
            json={"email": "nonexistent@test.com"},
        )
        assert resp.status_code == 400

    @patch("backend.api.auth_routes.get_settings")
    @patch("backend.api.auth_routes.get_user_by_email")
    def test_forgot_password_with_jwt_returns_200(self, mock_get_user, mock_settings, test_client):
        """With JWT configured, always returns success."""
        settings = MagicMock()
        settings.jwt_secret = "test-secret"
        mock_settings.return_value = settings
        mock_get_user.return_value = None  # no user found
        resp = test_client.post(
            "/api/auth/forgot-password",
            json={"email": "nonexistent@test.com"},
        )
        assert resp.status_code == 200

    @patch("backend.api.auth_routes.verify_password_reset_token")
    def test_reset_password_invalid_token(self, mock_verify, test_client):
        mock_verify.return_value = None
        resp = test_client.post(
            "/api/auth/reset-password",
            json={"token": "invalid-token", "new_password": "newpassword123"},
        )
        assert resp.status_code == 400

    @patch("backend.api.auth_routes.verify_email_token")
    def test_verify_email_invalid_token(self, mock_verify, test_client):
        mock_verify.return_value = None
        resp = test_client.post(
            "/api/auth/verify-email",
            json={"token": "invalid-token"},
        )
        assert resp.status_code == 400

    @patch("backend.api.auth_routes.get_user_by_email")
    def test_resend_verification_always_succeeds(self, mock_get_user, test_client):
        mock_get_user.return_value = None
        resp = test_client.post(
            "/api/auth/resend-verification",
            json={"email": "nonexistent@test.com"},
        )
        assert resp.status_code == 200
