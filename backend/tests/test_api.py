"""Tests for FastAPI endpoints."""

from unittest.mock import AsyncMock, patch


# ── Root & Health ────────────────────────────────────────────────────


def test_root(test_client):
    resp = test_client.get("/")
    assert resp.status_code == 200
    assert "Cybersecurity Threat Analyst API" in resp.json()["message"]


def test_health(test_client):
    resp = test_client.get("/api/health")
    assert resp.status_code == 200
    data = resp.json()
    assert "status" in data
    assert "ollama_connected" in data
    assert "qdrant_connected" in data


# ── CVE Endpoint ────────────────────────────────────────────────────


class TestCVEEndpoint:
    """Tests for GET /api/cve/{cve_id}."""

    @patch("backend.api.routes.fetch_cve", new_callable=AsyncMock)
    def test_get_cve_success(self, mock_fetch, test_client):
        mock_fetch.return_value = {
            "cve_id": "CVE-2021-44228",
            "description": "Log4j RCE",
            "cvss_score": 10.0,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
            "severity": "CRITICAL",
            "cwes": ["CWE-502"],
            "references": [],
            "published": "2021-12-10T10:15:00",
            "last_modified": "2023-04-03T20:15:00",
            "affected_products": ["cpe:2.3:a:apache:log4j:*"],
        }
        resp = test_client.get("/api/cve/CVE-2021-44228")
        assert resp.status_code == 200
        data = resp.json()
        assert data["cve_id"] == "CVE-2021-44228"
        assert data["cvss_score"] == 10.0
        assert data["severity"] == "CRITICAL"


# ── Recent Feed Endpoint ────────────────────────────────────────────


class TestRecentFeedEndpoint:
    """Tests for GET /api/feed/recent."""

    @patch("backend.api.routes.is_in_kev")
    @patch("backend.api.routes.fetch_recent_cves", new_callable=AsyncMock)
    def test_get_recent_feed(self, mock_fetch, mock_kev, test_client):
        mock_fetch.return_value = [
            {
                "cve_id": "CVE-2024-0001",
                "description": "Test vulnerability",
                "cvss_score": 7.5,
                "severity": "HIGH",
                "published": "2024-01-01",
                "cwes": ["CWE-79"],
            },
            {
                "cve_id": "CVE-2024-0002",
                "description": "Another vulnerability",
                "cvss_score": 5.0,
                "severity": "MEDIUM",
                "published": "2024-01-02",
                "cwes": [],
            },
        ]
        mock_kev.return_value = False

        resp = test_client.get("/api/feed/recent?days=3&limit=10")
        assert resp.status_code == 200
        data = resp.json()
        assert data["count"] == 2
        assert len(data["items"]) == 2
        assert data["items"][0]["cve_id"] == "CVE-2024-0001"
        assert data["items"][0]["in_kev"] is False

    @patch("backend.api.routes.is_in_kev")
    @patch("backend.api.routes.fetch_recent_cves", new_callable=AsyncMock)
    def test_recent_feed_with_kev(self, mock_fetch, mock_kev, test_client):
        mock_fetch.return_value = [
            {
                "cve_id": "CVE-2021-44228",
                "description": "Log4j",
                "cvss_score": 10.0,
                "severity": "CRITICAL",
                "published": "2021-12-10",
                "cwes": ["CWE-502"],
            },
        ]
        mock_kev.return_value = True

        resp = test_client.get("/api/feed/recent")
        data = resp.json()
        assert data["items"][0]["in_kev"] is True

    @patch("backend.api.routes.is_in_kev")
    @patch("backend.api.routes.fetch_recent_cves", new_callable=AsyncMock)
    def test_recent_feed_empty(self, mock_fetch, mock_kev, test_client):
        mock_fetch.return_value = []
        resp = test_client.get("/api/feed/recent")
        data = resp.json()
        assert data["count"] == 0
        assert data["items"] == []


# ── OTX Feed Endpoint ────────────────────────────────────────────────


class TestOTXFeedEndpoint:
    """Tests for GET /api/feed/otx."""

    @patch("backend.api.routes.fetch_otx_recent_pulses", new_callable=AsyncMock)
    def test_get_otx_feed(self, mock_fetch, test_client):
        mock_fetch.return_value = [
            {
                "pulse_id": "abc123",
                "name": "Log4Shell Tracking",
                "description": "Pulse for Log4Shell",
                "created": "2021-12-11",
                "tags": ["log4j", "rce"],
                "adversary": "APT41",
                "ioc_count": 15,
            },
        ]
        resp = test_client.get("/api/feed/otx?days=7&limit=20")
        assert resp.status_code == 200
        data = resp.json()
        assert data["count"] == 1
        assert data["items"][0]["pulse_id"] == "abc123"
        assert data["items"][0]["adversary"] == "APT41"

    @patch("backend.api.routes.fetch_otx_recent_pulses", new_callable=AsyncMock)
    def test_otx_feed_empty(self, mock_fetch, test_client):
        mock_fetch.return_value = []
        resp = test_client.get("/api/feed/otx")
        data = resp.json()
        assert data["count"] == 0
        assert data["items"] == []


# ── ThreatFox Feed Endpoint ──────────────────────────────────────────


class TestThreatFoxFeedEndpoint:
    """Tests for GET /api/feed/threatfox."""

    @patch("backend.api.routes.fetch_threatfox_recent", new_callable=AsyncMock)
    def test_get_threatfox_feed(self, mock_fetch, test_client):
        mock_fetch.return_value = [
            {
                "ioc_id": 12345,
                "ioc_type": "ip:port",
                "ioc_value": "1.2.3.4:443",
                "threat_type": "botnet_cc",
                "malware": "Cobalt Strike",
                "confidence_level": 75,
                "first_seen": "2024-01-01",
                "tags": ["cobalt-strike"],
            },
        ]
        resp = test_client.get("/api/feed/threatfox?days=3&limit=10")
        assert resp.status_code == 200
        data = resp.json()
        assert data["count"] == 1
        assert data["items"][0]["ioc_type"] == "ip:port"
        assert data["items"][0]["ioc_value"] == "1.2.3.4:443"

    @patch("backend.api.routes.fetch_threatfox_recent", new_callable=AsyncMock)
    def test_threatfox_feed_empty(self, mock_fetch, test_client):
        mock_fetch.return_value = []
        resp = test_client.get("/api/feed/threatfox")
        data = resp.json()
        assert data["count"] == 0


# ── Stats Endpoint ───────────────────────────────────────────────────


class TestStatsEndpoint:
    """Tests for GET /api/stats."""

    def test_get_stats_response_shape(self, test_client):
        """Stats endpoint returns correct shape regardless of service availability."""
        resp = test_client.get("/api/stats")
        data = resp.json()
        assert "total_chunks" in data
        assert "technique_chunks" in data
        assert "mitigation_chunks" in data
        assert "software_chunks" in data
        assert "group_chunks" in data
        assert "relationship_chunks" in data
        assert "ollama_connected" in data
        assert "qdrant_connected" in data


# ── Schema Validation ────────────────────────────────────────────────


class TestSchemas:
    """Test Pydantic schema models directly."""

    def test_analysis_request_defaults(self):
        from backend.api.schemas import AnalysisRequest

        req = AnalysisRequest()
        assert req.cve_id == ""
        assert req.cve_description == ""

    def test_analysis_request_with_data(self):
        from backend.api.schemas import AnalysisRequest

        req = AnalysisRequest(cve_id="CVE-2021-44228", cve_description="Log4j RCE")
        assert req.cve_id == "CVE-2021-44228"

    def test_feed_item_schema(self):
        from backend.api.schemas import FeedItem

        item = FeedItem(
            cve_id="CVE-2024-0001",
            description="Test",
            cvss_score=7.5,
            severity="HIGH",
            published="2024-01-01",
            cwes=["CWE-79"],
            in_kev=False,
        )
        assert item.cve_id == "CVE-2024-0001"

    def test_otx_pulse_item_defaults(self):
        from backend.api.schemas import OTXPulseItem

        item = OTXPulseItem(pulse_id="abc", name="Test Pulse")
        assert item.description == ""
        assert item.tags == []
        assert item.ioc_count == 0

    def test_threatfox_ioc_item_defaults(self):
        from backend.api.schemas import ThreatFoxIOCItem

        item = ThreatFoxIOCItem(ioc_type="ip:port", ioc_value="1.2.3.4:443")
        assert item.ioc_id == 0
        assert item.malware == ""
        assert item.confidence_level == 0

    def test_dashboard_stats_defaults(self):
        from backend.api.schemas import DashboardStats

        stats = DashboardStats()
        assert stats.total_chunks == 0
        assert stats.ollama_connected is False
