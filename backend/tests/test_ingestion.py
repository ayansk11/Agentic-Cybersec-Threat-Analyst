"""Tests for data ingestion modules (NVD, CISA KEV, OTX, ThreatFox)."""

import json
from unittest.mock import patch, MagicMock

import httpx
import pytest


# ── NVD Fetcher tests ─────────────────────────────────────────────────


class TestNVDParseCve:
    """Tests for _parse_cve helper in nvd_fetcher."""

    def test_parse_full_cve(self):
        from backend.ingestion.nvd_fetcher import _parse_cve
        cve = {
            "id": "CVE-2021-44228",
            "descriptions": [{"lang": "en", "value": "Log4j RCE vulnerability"}],
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
            "weaknesses": [{"description": [{"value": "CWE-502"}]}],
            "references": [{"url": "https://example.com", "source": "test"}],
            "published": "2021-12-10T10:15:00",
            "lastModified": "2023-04-03T20:15:00",
            "configurations": [
                {
                    "nodes": [
                        {
                            "cpeMatch": [
                                {"vulnerable": True, "criteria": "cpe:2.3:a:apache:log4j:*"}
                            ]
                        }
                    ]
                }
            ],
        }
        result = _parse_cve(cve)
        assert result["cve_id"] == "CVE-2021-44228"
        assert result["cvss_score"] == 10.0
        assert result["severity"] == "CRITICAL"
        assert "CWE-502" in result["cwes"]
        assert len(result["affected_products"]) == 1

    def test_parse_cve_no_metrics(self):
        from backend.ingestion.nvd_fetcher import _parse_cve
        cve = {
            "id": "CVE-2024-0001",
            "descriptions": [{"lang": "en", "value": "Some vuln"}],
            "metrics": {},
        }
        result = _parse_cve(cve)
        assert result["cvss_score"] is None
        assert result["severity"] == "UNKNOWN"

    def test_parse_cve_no_english_description(self):
        from backend.ingestion.nvd_fetcher import _parse_cve
        cve = {
            "id": "CVE-2024-0002",
            "descriptions": [{"lang": "es", "value": "Vulnerabilidad"}],
            "metrics": {},
        }
        result = _parse_cve(cve)
        assert result["description"] == "Vulnerabilidad"

    def test_parse_cve_fallback_cvss_v2(self):
        from backend.ingestion.nvd_fetcher import _parse_cve
        cve = {
            "id": "CVE-2020-0001",
            "descriptions": [{"lang": "en", "value": "Old vuln"}],
            "metrics": {
                "cvssMetricV2": [
                    {
                        "cvssData": {
                            "baseScore": 7.5,
                            "vectorString": "AV:N/AC:L/Au:N/C:P/I:P/A:P",
                            "baseSeverity": "HIGH",
                        }
                    }
                ]
            },
        }
        result = _parse_cve(cve)
        assert result["cvss_score"] == 7.5


class TestNVDFetchCve:
    """Tests for async fetch_cve function."""

    @pytest.mark.asyncio
    async def test_fetch_cve_success(self, sample_nvd_response):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = sample_nvd_response
        mock_response.raise_for_status = MagicMock()

        with patch("backend.ingestion.nvd_fetcher.httpx.AsyncClient") as mock_client_cls:
            mock_client = MagicMock()
            mock_client.__aenter__ = lambda self: _async_return(self)
            mock_client.__aexit__ = lambda self, *a: _async_return(None)
            mock_client.get = lambda *a, **kw: _async_return(mock_response)
            mock_client_cls.return_value = mock_client

            from backend.ingestion.nvd_fetcher import fetch_cve
            result = await fetch_cve("CVE-2021-44228")

        assert result["cve_id"] == "CVE-2021-44228"
        assert result["cvss_score"] == 10.0

    @pytest.mark.asyncio
    async def test_fetch_cve_not_found(self):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"vulnerabilities": []}
        mock_response.raise_for_status = MagicMock()

        with patch("backend.ingestion.nvd_fetcher.httpx.AsyncClient") as mock_client_cls:
            mock_client = MagicMock()
            mock_client.__aenter__ = lambda self: _async_return(self)
            mock_client.__aexit__ = lambda self, *a: _async_return(None)
            mock_client.get = lambda *a, **kw: _async_return(mock_response)
            mock_client_cls.return_value = mock_client

            from backend.ingestion.nvd_fetcher import fetch_cve
            result = await fetch_cve("CVE-9999-99999")

        assert "error" in result


# ── CISA KEV tests ────────────────────────────────────────────────────


class TestCISAKEV:
    """Tests for CISA KEV parsing and lookup."""

    def test_parse_kev_entry(self):
        from backend.ingestion.cisa_kev import _parse_kev_entry
        entry = {
            "cveID": "CVE-2021-44228",
            "vendorProject": "Apache",
            "product": "Log4j",
            "vulnerabilityName": "Log4Shell",
            "dateAdded": "2021-12-10",
            "dueDate": "2021-12-24",
            "requiredAction": "Apply updates",
            "knownRansomwareCampaignUse": "Known",
        }
        result = _parse_kev_entry(entry)
        assert result["cve_id"] == "CVE-2021-44228"
        assert result["vendor"] == "Apache"
        assert result["known_ransomware"] == "Known"

    def test_is_in_kev_with_cached_data(self, tmp_path):
        from backend.ingestion import cisa_kev
        # Write a temp cache file
        cache = {
            "vulnerabilities": [
                {"cveID": "CVE-2021-44228", "vendorProject": "Apache", "product": "Log4j",
                 "vulnerabilityName": "Log4Shell", "dateAdded": "2021-12-10",
                 "dueDate": "2021-12-24", "requiredAction": "Apply updates"}
            ]
        }
        cache_file = tmp_path / "cisa_kev.json"
        cache_file.write_text(json.dumps(cache))

        original_path = cisa_kev.KEV_CACHE_PATH
        cisa_kev.KEV_CACHE_PATH = cache_file
        try:
            assert cisa_kev.is_in_kev("CVE-2021-44228") is True
            assert cisa_kev.is_in_kev("CVE-9999-99999") is False
        finally:
            cisa_kev.KEV_CACHE_PATH = original_path


# ── OTX Fetcher tests ────────────────────────────────────────────────


class TestOTXFetcher:
    """Tests for AlienVault OTX fetcher."""

    def test_parse_pulse(self):
        from backend.ingestion.otx_fetcher import _parse_pulse
        pulse = {
            "id": "abc123",
            "name": "Test Pulse",
            "description": "A test pulse",
            "created": "2024-01-01T00:00:00",
            "tags": ["test", "malware"],
            "adversary": "APT28",
            "indicators": [
                {"type": "IPv4", "indicator": "1.2.3.4", "description": "C2"},
                {"type": "domain", "indicator": "evil.com", "description": ""},
            ],
        }
        result = _parse_pulse(pulse)
        assert result["pulse_id"] == "abc123"
        assert result["adversary"] == "APT28"
        assert result["ioc_count"] == 2
        assert len(result["iocs"]) == 2
        assert result["iocs"][0]["type"] == "IPv4"

    def test_parse_pulse_no_adversary(self):
        from backend.ingestion.otx_fetcher import _parse_pulse
        pulse = {"id": "x", "name": "Test", "description": "", "indicators": [], "adversary": None}
        result = _parse_pulse(pulse)
        assert result["adversary"] == ""

    @pytest.mark.asyncio
    async def test_fetch_otx_no_api_key(self):
        """Without an API key, OTX fetcher returns empty list."""
        with patch("backend.ingestion.otx_fetcher.get_settings") as mock_settings:
            mock_settings.return_value = MagicMock(otx_api_key="", otx_base_url="https://otx.alienvault.com/api/v1")

            from backend.ingestion.otx_fetcher import fetch_otx_pulse_by_cve
            result = await fetch_otx_pulse_by_cve("CVE-2021-44228")
            assert result == []


# ── ThreatFox Fetcher tests ──────────────────────────────────────────


class TestThreatFoxFetcher:
    """Tests for abuse.ch ThreatFox fetcher."""

    def test_parse_threatfox_ioc(self):
        from backend.ingestion.abusech_fetcher import _parse_threatfox_ioc
        entry = {
            "id": 12345,
            "ioc_type": "ip:port",
            "ioc": "1.2.3.4:443",
            "threat_type": "botnet_cc",
            "malware_printable": "Cobalt Strike",
            "confidence_level": 75,
            "first_seen_utc": "2024-01-01 00:00:00",
            "tags": ["cobalt-strike"],
        }
        result = _parse_threatfox_ioc(entry)
        assert result["ioc_id"] == 12345
        assert result["ioc_type"] == "ip:port"
        assert result["ioc_value"] == "1.2.3.4:443"
        assert result["malware"] == "Cobalt Strike"
        assert result["confidence_level"] == 75

    def test_parse_threatfox_ioc_missing_fields(self):
        from backend.ingestion.abusech_fetcher import _parse_threatfox_ioc
        entry = {"ioc_type": "url", "ioc": "http://evil.com/payload"}
        result = _parse_threatfox_ioc(entry)
        assert result["ioc_id"] == 0
        assert result["malware"] == ""
        assert result["confidence_level"] == 0
        assert result["tags"] == []

    @pytest.mark.asyncio
    async def test_fetch_threatfox_by_cve_success(self, sample_threatfox_response):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = sample_threatfox_response
        mock_response.raise_for_status = MagicMock()

        with patch("backend.ingestion.abusech_fetcher.httpx.AsyncClient") as mock_client_cls:
            mock_client = MagicMock()
            mock_client.__aenter__ = lambda self: _async_return(self)
            mock_client.__aexit__ = lambda self, *a: _async_return(None)
            mock_client.post = lambda *a, **kw: _async_return(mock_response)
            mock_client_cls.return_value = mock_client

            from backend.ingestion.abusech_fetcher import fetch_threatfox_by_cve
            result = await fetch_threatfox_by_cve("CVE-2021-44228")

        assert len(result) == 2
        assert result[0]["ioc_value"] == "1.2.3.4:443"

    @pytest.mark.asyncio
    async def test_fetch_threatfox_no_results(self):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"query_status": "no_result", "data": None}
        mock_response.raise_for_status = MagicMock()

        with patch("backend.ingestion.abusech_fetcher.httpx.AsyncClient") as mock_client_cls:
            mock_client = MagicMock()
            mock_client.__aenter__ = lambda self: _async_return(self)
            mock_client.__aexit__ = lambda self, *a: _async_return(None)
            mock_client.post = lambda *a, **kw: _async_return(mock_response)
            mock_client_cls.return_value = mock_client

            from backend.ingestion.abusech_fetcher import fetch_threatfox_by_cve
            result = await fetch_threatfox_by_cve("CVE-9999-99999")

        assert result == []

    @pytest.mark.asyncio
    async def test_fetch_threatfox_http_error(self):
        with patch("backend.ingestion.abusech_fetcher.httpx.AsyncClient") as mock_client_cls:
            mock_client = MagicMock()
            mock_client.__aenter__ = lambda self: _async_return(self)
            mock_client.__aexit__ = lambda self, *a: _async_return(None)
            mock_client.post = lambda *a, **kw: _async_raise(httpx.TimeoutException("timeout"))
            mock_client_cls.return_value = mock_client

            from backend.ingestion.abusech_fetcher import fetch_threatfox_by_cve
            result = await fetch_threatfox_by_cve("CVE-2021-44228")

        assert result == []


# ── Async helpers ─────────────────────────────────────────────────────

async def _async_return(val):
    return val

async def _async_raise(exc):
    raise exc
