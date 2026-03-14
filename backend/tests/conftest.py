"""Shared test fixtures for the backend test suite."""

import pytest
from fastapi.testclient import TestClient
from unittest.mock import MagicMock

from backend.api.auth import CurrentUser, get_current_user
from backend.main import app


# ── Auth fixtures ───────────────────────────────────────────────────────

MOCK_ADMIN = CurrentUser(id=1, email="admin@test.com", username="Admin", role="admin")

MOCK_ANALYST = CurrentUser(id=2, email="analyst@test.com", username="Analyst", role="analyst")


@pytest.fixture(autouse=True)
def mock_auth():
    """Override get_current_user dependency to return admin for all tests.

    Uses FastAPI's dependency_overrides which works regardless of import path.
    """
    app.dependency_overrides[get_current_user] = lambda: MOCK_ADMIN
    yield
    app.dependency_overrides.pop(get_current_user, None)


# ── Settings fixtures ──────────────────────────────────────────────────


@pytest.fixture(autouse=True)
def clear_settings_cache():
    """Clear LRU-cached settings between tests to prevent cross-test contamination."""
    from backend.config import get_settings

    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


# ── Cache fixtures ──────────────────────────────────────────────────────


@pytest.fixture(autouse=True)
def clear_caches():
    """Clear in-memory caches between tests to prevent cross-test contamination."""
    from backend.cache import cve_cache, feed_cache

    cve_cache.clear()
    feed_cache.clear()
    yield
    cve_cache.clear()
    feed_cache.clear()


# ── Client fixtures ─────────────────────────────────────────────────────


@pytest.fixture
def test_client():
    """FastAPI test client."""
    return TestClient(app)


# ── Agent fixtures ──────────────────────────────────────────────────────


@pytest.fixture
def sample_state():
    """Sample ThreatAnalysisState for agent tests."""
    return {
        "cve_id": "CVE-2021-44228",
        "cve_description": (
            "Apache Log4j2 2.0-beta9 through 2.15.0 JNDI features do not protect "
            "against attacker controlled LDAP and other JNDI related endpoints."
        ),
        "extracted_info": {},
        "attack_techniques": [],
        "rag_context": "",
        "response_playbook": "",
        "sigma_rule": "",
        "messages": [],
    }


@pytest.fixture
def sample_extracted_info():
    """Sample Agent 1 output."""
    return {
        "summary": "Critical RCE in Apache Log4j2 via JNDI injection",
        "severity_assessment": "CRITICAL - actively exploited, trivial to exploit",
        "attack_vector": "Network",
        "attack_complexity": "Low",
        "privileges_required": "None",
        "user_interaction": "None",
        "affected_software": ["Apache Log4j2 2.0-beta9 through 2.15.0"],
        "cwe_category": "CWE-502 Deserialization of Untrusted Data",
        "vulnerability_type": "Remote Code Execution",
        "potential_impact": "Full system compromise via arbitrary code execution",
        "iocs": [],
        "key_risk_factors": ["No authentication required", "Network accessible"],
        "exploitation_likelihood": "Active",
        "recommended_priority": "Immediate",
        "nvd_cvss_score": 10.0,
        "nvd_severity": "CRITICAL",
        "nvd_cwes": ["CWE-502"],
        "cisa_kev": True,
        "cve_id": "CVE-2021-44228",
    }


@pytest.fixture
def sample_nvd_response():
    """Sample NVD API response for CVE-2021-44228."""
    return {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2021-44228",
                    "descriptions": [
                        {
                            "lang": "en",
                            "value": "Apache Log4j2 RCE vulnerability via JNDI",
                        }
                    ],
                    "metrics": {
                        "cvssMetricV31": [
                            {
                                "cvssData": {
                                    "baseScore": 10.0,
                                    "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                                    "baseSeverity": "CRITICAL",
                                }
                            }
                        ]
                    },
                    "weaknesses": [
                        {
                            "description": [{"value": "CWE-502"}],
                        }
                    ],
                    "references": [
                        {
                            "url": "https://logging.apache.org/log4j/2.x/security.html",
                            "source": "apache",
                        },
                    ],
                    "published": "2021-12-10T10:15:00",
                    "lastModified": "2023-04-03T20:15:00",
                    "configurations": [
                        {
                            "nodes": [
                                {
                                    "cpeMatch": [
                                        {
                                            "vulnerable": True,
                                            "criteria": "cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*",
                                        }
                                    ]
                                }
                            ]
                        }
                    ],
                }
            }
        ]
    }


@pytest.fixture
def sample_otx_response():
    """Sample OTX API response."""
    return {
        "pulse_info": {
            "pulses": [
                {
                    "id": "pulse-123",
                    "name": "Log4Shell Exploitation",
                    "description": "Tracking Log4Shell exploitation attempts",
                    "created": "2021-12-11T00:00:00",
                    "tags": ["log4j", "rce", "log4shell"],
                    "adversary": "APT41",
                    "indicators": [
                        {"type": "IPv4", "indicator": "1.2.3.4", "description": "C2 server"},
                        {
                            "type": "domain",
                            "indicator": "evil.com",
                            "description": "Callback domain",
                        },
                    ],
                }
            ]
        }
    }


@pytest.fixture
def sample_threatfox_response():
    """Sample ThreatFox API response."""
    return {
        "query_status": "ok",
        "data": [
            {
                "id": 12345,
                "ioc_type": "ip:port",
                "ioc": "1.2.3.4:443",
                "threat_type": "botnet_cc",
                "malware_printable": "Cobalt Strike",
                "confidence_level": 75,
                "first_seen_utc": "2021-12-12 10:00:00",
                "tags": ["log4j", "cobalt-strike"],
            },
            {
                "id": 12346,
                "ioc_type": "domain",
                "ioc": "malware.example.com",
                "threat_type": "payload_delivery",
                "malware_printable": "Log4Shell Exploit",
                "confidence_level": 90,
                "first_seen_utc": "2021-12-13 08:00:00",
                "tags": ["log4shell"],
            },
        ],
    }


@pytest.fixture
def mock_llm():
    """Mock LLM that returns configurable responses."""
    llm = MagicMock()
    response = MagicMock()
    response.content = '{"summary": "test vulnerability", "severity_assessment": "HIGH"}'
    llm.invoke.return_value = response
    return llm
