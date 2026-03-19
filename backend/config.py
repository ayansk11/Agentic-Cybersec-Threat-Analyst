"""Application configuration via environment variables."""

from functools import lru_cache

import httpx
from pydantic_settings import BaseSettings

# ── Model Registry ──────────────────────────────────────────────────────

AVAILABLE_MODELS: dict[str, dict] = {
    "foundation-sec-8b": {
        "ollama_name": "hf.co/fdtn-ai/Foundation-Sec-8B-Reasoning-Q4_K_M-GGUF",
        "display_name": "Foundation-Sec-8B",
        "description": "Cisco security-focused 8B reasoning model (Q4_K_M quantization)",
        "size": "4.9 GB",
        "default": True,
    },
    "deephat-v1-7b": {
        "ollama_name": "hf.co/mradermacher/DeepHat-V1-7B-GGUF:Q4_K_M",
        "display_name": "DeepHat-V1-7B",
        "description": "Cybersecurity-tuned 7B model for threat analysis (Q4_K_M quantization)",
        "size": "4.8 GB",
        "default": False,
    },
}

DEFAULT_MODEL_ID = next(k for k, v in AVAILABLE_MODELS.items() if v.get("default"))


class Settings(BaseSettings):
    # LLM
    llm_provider: str = "ollama"
    ollama_base_url: str = "http://localhost:11434"
    ollama_model: str = "hf.co/fdtn-ai/Foundation-Sec-8B-Reasoning-Q4_K_M-GGUF"
    groq_api_key: str = ""
    groq_model: str = "llama-3.1-8b-instant"

    # Qdrant
    qdrant_host: str = "localhost"
    qdrant_port: int = 6333
    qdrant_collection: str = "mitre_attack"

    # AlienVault OTX
    otx_api_key: str = ""
    otx_base_url: str = "https://otx.alienvault.com/api/v1"

    # ThreatFox (abuse.ch)
    threatfox_api_key: str = ""

    # NVD
    nvd_api_key: str = ""
    nvd_base_url: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    # CISA KEV
    cisa_kev_url: str = (
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    )

    # MITRE ATT&CK
    attack_stix_url: str = (
        "https://raw.githubusercontent.com/mitre-attack/attack-stix-data"
        "/master/enterprise-attack/enterprise-attack.json"
    )
    attack_data_path: str = "data/enterprise-attack.json"

    # API
    api_host: str = "0.0.0.0"
    api_port: int = 8000

    # Logging
    log_level: str = "INFO"

    # CORS (comma-separated origins)
    cors_origins: str = "http://localhost:5173,http://localhost:80"

    # Authentication (empty = auth disabled)
    api_key: str = ""

    # JWT Authentication (empty jwt_secret = JWT auth disabled, backward compat)
    jwt_secret: str = ""
    jwt_algorithm: str = "HS256"
    jwt_access_expire_minutes: int = 15
    jwt_refresh_expire_days: int = 7

    # OAuth2 - Google
    google_client_id: str = ""
    google_client_secret: str = ""
    google_redirect_uri: str = "http://localhost:8000/api/auth/oauth/google/callback"

    # OAuth2 - GitHub
    github_client_id: str = ""
    github_client_secret: str = ""
    github_redirect_uri: str = "http://localhost:8000/api/auth/oauth/github/callback"

    # Frontend URL (for OAuth redirect back to SPA)
    frontend_url: str = "http://localhost:5173"

    # Initial admin seed (optional, auto-creates first admin on startup)
    admin_email: str = ""
    admin_password: str = ""

    # Rate limiting
    rate_limit_analyze: str = "5/minute"
    rate_limit_feed: str = "30/minute"

    # Caching TTLs (seconds)
    cache_ttl_cve: int = 3600
    cache_ttl_feed: int = 900

    # SMTP Email (empty smtp_host = email disabled, tokens logged to console)
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_password: str = ""
    smtp_from_email: str = "noreply@threatanalyst.local"
    smtp_from_name: str = "ThreatAnalyst"
    smtp_use_tls: bool = True

    # Webhooks
    webhook_url: str = ""
    webhook_severity_threshold: str = "HIGH"

    # Cookie security (set True in production behind HTTPS)
    cookie_secure: bool = True

    model_config = {"env_file": ".env", "env_file_encoding": "utf-8"}


@lru_cache
def get_settings() -> Settings:
    return Settings()


def get_llm(model_id: str | None = None):
    """Return the configured LLM client.

    Args:
        model_id: Optional model registry key (e.g. "foundation-sec-8b", "deephat-v1-7b").
                  Falls back to the default model if not specified.
    """
    settings = get_settings()

    if settings.llm_provider == "groq":
        from langchain_groq import ChatGroq

        return ChatGroq(
            model=settings.groq_model,
            api_key=settings.groq_api_key,
            temperature=0,
            timeout=60,
        )

    from langchain_ollama import ChatOllama

    # Resolve model name from registry, or fall back to settings
    ollama_model = settings.ollama_model
    if model_id and model_id in AVAILABLE_MODELS:
        ollama_model = AVAILABLE_MODELS[model_id]["ollama_name"]

    # timeout applies to both sync (invoke) and async (ainvoke) calls
    _timeout = httpx.Timeout(timeout=300.0, connect=30.0)
    return ChatOllama(
        model=ollama_model,
        base_url=settings.ollama_base_url,
        temperature=0,
        num_predict=4096,
        num_ctx=8192,
        client_kwargs={"timeout": _timeout},
        sync_client_kwargs={"timeout": _timeout},
    )
