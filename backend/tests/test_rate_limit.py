"""Tests for rate limiting."""

from fastapi.testclient import TestClient

from backend.main import app

client = TestClient(app)


class TestRateLimiting:
    def test_health_not_rate_limited(self):
        """Health endpoint should not be rate limited."""
        for _ in range(20):
            resp = client.get("/api/health")
            assert resp.status_code == 200
