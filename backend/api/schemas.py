"""Pydantic models for API request/response schemas."""

from pydantic import BaseModel, Field


class AnalysisRequest(BaseModel):
    cve_id: str = Field(
        default="", max_length=20, description="CVE identifier (e.g., CVE-2021-44228)"
    )
    cve_description: str = Field(
        default="", max_length=10_000, description="Raw vulnerability description text"
    )
    model: str | None = Field(
        default=None, max_length=50, description="Model ID to use (e.g., 'foundation-sec-8b')"
    )


class AnalysisResponse(BaseModel):
    cve_id: str
    extracted_info: dict
    attack_techniques: list[dict]
    response_playbook: str
    sigma_rule: str


class CVEResponse(BaseModel):
    cve_id: str
    description: str
    cvss_score: float | None
    cvss_vector: str | None
    severity: str
    cwes: list[str]
    published: str | None
    affected_products: list[str]


class HealthResponse(BaseModel):
    status: str
    ollama_connected: bool
    qdrant_connected: bool


class FeedItem(BaseModel):
    cve_id: str
    description: str
    cvss_score: float | None
    severity: str
    published: str | None
    cwes: list[str]
    in_kev: bool


class FeedResponse(BaseModel):
    items: list[FeedItem]
    count: int


class OTXPulseItem(BaseModel):
    pulse_id: str
    name: str
    description: str = ""
    created: str | None = None
    tags: list[str] = []
    adversary: str = ""
    ioc_count: int = 0


class OTXFeedResponse(BaseModel):
    items: list[OTXPulseItem]
    count: int


class ThreatFoxIOCItem(BaseModel):
    ioc_id: int = 0
    ioc_type: str
    ioc_value: str
    threat_type: str = ""
    malware: str = ""
    confidence_level: int = 0
    first_seen: str | None = None
    tags: list[str] = []


class ThreatFoxFeedResponse(BaseModel):
    items: list[ThreatFoxIOCItem]
    count: int


class DashboardStats(BaseModel):
    total_chunks: int = 0
    technique_chunks: int = 0
    mitigation_chunks: int = 0
    software_chunks: int = 0
    group_chunks: int = 0
    relationship_chunks: int = 0
    ollama_connected: bool = False
    qdrant_connected: bool = False


class AnalysisHistoryItem(BaseModel):
    id: int
    cve_id: str
    cve_description: str = ""
    severity: str = "UNKNOWN"
    created_at: str
    extracted_info: dict = {}
    attack_techniques: list[dict] = []
    response_playbook: str = ""
    sigma_rule: str = ""
    user_id: int | None = None


class AnalysisHistoryResponse(BaseModel):
    items: list[AnalysisHistoryItem]
    count: int


class SeverityStatsResponse(BaseModel):
    counts: dict[str, int] = {}


class TacticStatsResponse(BaseModel):
    counts: dict[str, int] = {}


# ── Auth schemas ────────────────────────────────────────────────────────


class RegisterRequest(BaseModel):
    email: str
    username: str = Field(min_length=2, max_length=50)
    password: str = Field(min_length=8, max_length=128)


class LoginRequest(BaseModel):
    email: str
    password: str


class UserResponse(BaseModel):
    id: int
    email: str
    username: str
    role: str
    oauth_provider: str | None = None
    is_active: bool = True
    email_verified: bool = False
    created_at: str


class AuthResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserResponse


class UserUpdateRequest(BaseModel):
    role: str | None = None
    is_active: bool | None = None


class UsersListResponse(BaseModel):
    users: list[UserResponse]
    count: int


class PasswordResetRequest(BaseModel):
    email: str


class PasswordResetConfirm(BaseModel):
    token: str
    new_password: str = Field(min_length=8, max_length=128)


class VerifyEmailRequest(BaseModel):
    token: str


class ResendVerificationRequest(BaseModel):
    email: str


class AuthProvidersResponse(BaseModel):
    local: bool = True
    google: bool = False
    github: bool = False
    jwt_configured: bool = False


# ── Settings schemas ──────────────────────────────────────────────────


class WebhookSettingsResponse(BaseModel):
    webhook_url: str = ""
    webhook_severity_threshold: str = "HIGH"
    smtp_configured: bool = False


class WebhookSettingsUpdate(BaseModel):
    webhook_url: str = ""
    webhook_severity_threshold: str = Field(
        default="HIGH",
        pattern="^(CRITICAL|HIGH|MEDIUM|LOW)$",
    )


class WebhookTestRequest(BaseModel):
    url: str = Field(max_length=2048)
