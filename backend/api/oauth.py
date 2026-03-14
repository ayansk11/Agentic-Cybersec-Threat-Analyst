"""OAuth2 provider clients for Google and GitHub."""

import secrets
from dataclasses import dataclass
from urllib.parse import urlencode

import httpx

from backend.config import get_settings


@dataclass
class OAuthUserInfo:
    """Normalized user info returned by any OAuth provider."""

    provider: str
    oauth_id: str
    email: str
    username: str


class GoogleOAuth:
    """Google OAuth2 authorization code flow."""

    AUTHORIZE_URL = "https://accounts.google.com/o/oauth2/v2/auth"
    TOKEN_URL = "https://oauth2.googleapis.com/token"
    USERINFO_URL = "https://www.googleapis.com/oauth2/v2/userinfo"

    def __init__(self) -> None:
        settings = get_settings()
        self.client_id = settings.google_client_id
        self.client_secret = settings.google_client_secret
        self.redirect_uri = settings.google_redirect_uri

    @property
    def is_configured(self) -> bool:
        return bool(self.client_id and self.client_secret)

    def get_authorize_url(self, state: str) -> str:
        """Build the Google OAuth2 authorization URL."""
        params = {
            "client_id": self.client_id,
            "redirect_uri": self.redirect_uri,
            "response_type": "code",
            "scope": "openid email profile",
            "state": state,
            "access_type": "offline",
            "prompt": "consent",
        }
        return f"{self.AUTHORIZE_URL}?{urlencode(params)}"

    async def exchange_code(self, code: str) -> dict:
        """Exchange authorization code for access token."""
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(
                self.TOKEN_URL,
                data={
                    "client_id": self.client_id,
                    "client_secret": self.client_secret,
                    "code": code,
                    "grant_type": "authorization_code",
                    "redirect_uri": self.redirect_uri,
                },
            )
            resp.raise_for_status()
            return resp.json()

    async def get_user_info(self, access_token: str) -> OAuthUserInfo:
        """Fetch user profile from Google."""
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(
                self.USERINFO_URL,
                headers={"Authorization": f"Bearer {access_token}"},
            )
            resp.raise_for_status()
            data = resp.json()

        return OAuthUserInfo(
            provider="google",
            oauth_id=str(data["id"]),
            email=data["email"],
            username=data.get("name", data["email"].split("@")[0]),
        )


class GitHubOAuth:
    """GitHub OAuth2 authorization code flow."""

    AUTHORIZE_URL = "https://github.com/login/oauth/authorize"
    TOKEN_URL = "https://github.com/login/oauth/access_token"
    USER_URL = "https://api.github.com/user"
    EMAILS_URL = "https://api.github.com/user/emails"

    def __init__(self) -> None:
        settings = get_settings()
        self.client_id = settings.github_client_id
        self.client_secret = settings.github_client_secret
        self.redirect_uri = settings.github_redirect_uri

    @property
    def is_configured(self) -> bool:
        return bool(self.client_id and self.client_secret)

    def get_authorize_url(self, state: str) -> str:
        """Build the GitHub OAuth2 authorization URL."""
        params = {
            "client_id": self.client_id,
            "redirect_uri": self.redirect_uri,
            "scope": "read:user user:email",
            "state": state,
        }
        return f"{self.AUTHORIZE_URL}?{urlencode(params)}"

    async def exchange_code(self, code: str) -> dict:
        """Exchange authorization code for access token."""
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(
                self.TOKEN_URL,
                data={
                    "client_id": self.client_id,
                    "client_secret": self.client_secret,
                    "code": code,
                },
                headers={"Accept": "application/json"},
            )
            resp.raise_for_status()
            return resp.json()

    async def get_user_info(self, access_token: str) -> OAuthUserInfo:
        """Fetch user profile and primary email from GitHub."""
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Accept": "application/json",
        }
        async with httpx.AsyncClient(timeout=10.0) as client:
            # Get user profile
            resp = await client.get(self.USER_URL, headers=headers)
            resp.raise_for_status()
            user_data = resp.json()

            # Get primary email (may not be public on profile)
            email = user_data.get("email")
            if not email:
                resp = await client.get(self.EMAILS_URL, headers=headers)
                resp.raise_for_status()
                emails = resp.json()
                primary = next(
                    (e for e in emails if e.get("primary")),
                    emails[0] if emails else None,
                )
                email = primary["email"] if primary else f"{user_data['id']}@github"

        return OAuthUserInfo(
            provider="github",
            oauth_id=str(user_data["id"]),
            email=email,
            username=user_data.get("login", email.split("@")[0]),
        )


# ── Provider factory ───────────────────────────────────────────────────

_PROVIDERS = {
    "google": GoogleOAuth,
    "github": GitHubOAuth,
}


def get_oauth_provider(name: str) -> GoogleOAuth | GitHubOAuth:
    """Get an OAuth provider instance by name."""
    cls = _PROVIDERS.get(name)
    if not cls:
        raise ValueError(f"Unknown OAuth provider: {name}. Choose from: {list(_PROVIDERS)}")
    return cls()


def generate_state() -> str:
    """Generate a random state parameter for CSRF protection."""
    return secrets.token_urlsafe(32)
