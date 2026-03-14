"""Tests for Prometheus metrics endpoint."""

from fastapi.testclient import TestClient

from backend.main import app

client = TestClient(app)


class TestMetricsEndpoint:
    def test_metrics_returns_200(self):
        resp = client.get("/metrics")
        assert resp.status_code == 200

    def test_metrics_contains_http_metrics(self):
        # Make a request first to generate metrics
        client.get("/api/health")
        resp = client.get("/metrics")
        assert "http_request" in resp.text or "http_requests" in resp.text

    def test_metrics_no_auth_required(self):
        """Metrics endpoint should always be public."""
        resp = client.get("/metrics")
        assert resp.status_code == 200
