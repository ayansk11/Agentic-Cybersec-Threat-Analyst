"""Tests for structured logging configuration."""

import logging

from fastapi.testclient import TestClient

from backend.logging_config import RequestIDFilter, setup_logging
from backend.main import app

client = TestClient(app)


class TestRequestIDFilter:
    def test_filter_adds_request_id(self):
        filt = RequestIDFilter()
        record = logging.LogRecord("test", logging.INFO, "", 0, "msg", (), None)
        assert filt.filter(record) is True
        assert hasattr(record, "request_id")

    def test_filter_default_request_id(self):
        filt = RequestIDFilter()
        record = logging.LogRecord("test", logging.INFO, "", 0, "msg", (), None)
        filt.filter(record)
        assert record.request_id == "-"


class TestSetupLogging:
    def test_sets_level(self):
        setup_logging("DEBUG")
        logger = logging.getLogger("backend")
        assert logger.level == logging.DEBUG
        # Reset
        setup_logging("INFO")

    def test_sets_info_by_default(self):
        setup_logging()
        logger = logging.getLogger("backend")
        assert logger.level == logging.INFO


class TestRequestLoggingMiddleware:
    def test_adds_request_id_header(self):
        resp = client.get("/api/health")
        assert "X-Request-ID" in resp.headers

    def test_uses_provided_request_id(self):
        resp = client.get("/api/health", headers={"X-Request-ID": "test-123"})
        assert resp.headers["X-Request-ID"] == "test-123"
