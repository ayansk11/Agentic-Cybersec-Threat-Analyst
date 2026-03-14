"""Tests for in-memory caching layer."""

from unittest.mock import patch, MagicMock, AsyncMock


class TestCVECache:
    async def test_cache_hit_skips_http(self):
        """Second call to fetch_cve should return cached result without HTTP call."""
        from backend.cache import cve_cache

        # Pre-populate cache
        cve_cache["CVE-2021-44228"] = {"cve_id": "CVE-2021-44228", "cached": True}

        from backend.ingestion.nvd_fetcher import fetch_cve

        result = await fetch_cve("CVE-2021-44228")
        assert result["cached"] is True

        # Cleanup
        del cve_cache["CVE-2021-44228"]

    async def test_cache_miss_fetches(self):
        """First call should make HTTP request and populate cache."""
        from backend.cache import cve_cache

        # Ensure not cached
        cve_cache.pop("CVE-TEST-001", None)

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-TEST-001",
                        "descriptions": [{"lang": "en", "value": "Test"}],
                        "metrics": {},
                        "weaknesses": [],
                        "references": [],
                        "configurations": [],
                    }
                }
            ]
        }
        mock_response.raise_for_status = MagicMock()

        async def mock_get(*args, **kwargs):
            return mock_response

        mock_client = MagicMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)
        mock_client.get = mock_get

        with patch("backend.ingestion.nvd_fetcher.httpx.AsyncClient", return_value=mock_client):
            from backend.ingestion.nvd_fetcher import fetch_cve

            result = await fetch_cve("CVE-TEST-001")

        assert result["cve_id"] == "CVE-TEST-001"
        assert "CVE-TEST-001" in cve_cache

        # Cleanup
        cve_cache.pop("CVE-TEST-001", None)


class TestOTXCache:
    async def test_cache_hit(self):
        from backend.cache import cve_cache

        cve_cache["otx:CVE-2021-44228"] = [{"pulse_id": "cached"}]

        from backend.ingestion.otx_fetcher import fetch_otx_pulse_by_cve

        result = await fetch_otx_pulse_by_cve("CVE-2021-44228")
        assert result[0]["pulse_id"] == "cached"

        del cve_cache["otx:CVE-2021-44228"]


class TestThreatFoxCache:
    async def test_cache_hit(self):
        from backend.cache import cve_cache

        cve_cache["threatfox:CVE-2021-44228"] = [{"ioc_type": "cached"}]

        from backend.ingestion.abusech_fetcher import fetch_threatfox_by_cve

        result = await fetch_threatfox_by_cve("CVE-2021-44228")
        assert result[0]["ioc_type"] == "cached"

        del cve_cache["threatfox:CVE-2021-44228"]
