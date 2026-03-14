"""Tests for webhook notifications."""

from unittest.mock import patch, MagicMock, AsyncMock


from backend.webhooks import _meets_threshold, send_webhook


class TestMeetsThreshold:
    def test_critical_meets_high(self):
        assert _meets_threshold("CRITICAL", "HIGH") is True

    def test_high_meets_high(self):
        assert _meets_threshold("HIGH", "HIGH") is True

    def test_medium_does_not_meet_high(self):
        assert _meets_threshold("MEDIUM", "HIGH") is False

    def test_low_does_not_meet_high(self):
        assert _meets_threshold("LOW", "HIGH") is False

    def test_critical_meets_critical(self):
        assert _meets_threshold("CRITICAL", "CRITICAL") is True

    def test_high_does_not_meet_critical(self):
        assert _meets_threshold("HIGH", "CRITICAL") is False

    def test_unknown_does_not_meet_any(self):
        assert _meets_threshold("UNKNOWN", "LOW") is False

    def test_handles_severity_with_text(self):
        """Severity like 'CRITICAL - actively exploited' should work."""
        assert _meets_threshold("CRITICAL - actively exploited", "HIGH") is True


class TestSendWebhook:
    @patch("backend.webhooks._get_webhook_config", new_callable=AsyncMock, return_value=("", "HIGH"))
    async def test_noop_when_no_url(self, mock_config):
        # Should return without error when no URL configured
        await send_webhook("CVE-2021-44228", "CRITICAL", "summary", [])

    @patch("backend.webhooks._get_webhook_config", new_callable=AsyncMock, return_value=("https://example.com/hook", "HIGH"))
    async def test_noop_below_threshold(self, mock_config):
        # MEDIUM is below HIGH threshold
        await send_webhook("CVE-2024-0001", "MEDIUM", "summary", [])

    @patch("backend.webhooks.httpx.AsyncClient")
    @patch("backend.webhooks._get_webhook_config", new_callable=AsyncMock, return_value=("https://example.com/hook", "HIGH"))
    async def test_sends_post(self, mock_config, mock_client_cls):
        mock_client = MagicMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)
        mock_client.post = AsyncMock()
        mock_client_cls.return_value = mock_client

        await send_webhook(
            "CVE-2021-44228",
            "CRITICAL",
            "Log4j RCE",
            [{"technique_id": "T1190", "name": "Exploit App"}],
        )

        mock_client.post.assert_called_once()
        call_args = mock_client.post.call_args
        assert call_args[0][0] == "https://example.com/hook"
        payload = call_args[1]["json"]
        assert payload["cve_id"] == "CVE-2021-44228"
        assert payload["severity"] == "CRITICAL"

    @patch("backend.webhooks.httpx.AsyncClient")
    @patch("backend.webhooks._get_webhook_config", new_callable=AsyncMock, return_value=("https://example.com/hook", "HIGH"))
    async def test_handles_http_error(self, mock_config, mock_client_cls):
        """Webhook errors should be caught, not raised."""
        mock_client = MagicMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)
        mock_client.post = AsyncMock(side_effect=Exception("Connection refused"))
        mock_client_cls.return_value = mock_client

        # Should not raise
        await send_webhook("CVE-2021-44228", "CRITICAL", "summary", [])
