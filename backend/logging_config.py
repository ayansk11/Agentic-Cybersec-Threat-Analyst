"""Structured logging configuration with request ID tracking."""

import logging
import time
import uuid
from contextvars import ContextVar

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

request_id_var: ContextVar[str] = ContextVar("request_id", default="-")


class RequestIDFilter(logging.Filter):
    """Inject request_id into every log record."""

    def filter(self, record):
        record.request_id = request_id_var.get("-")
        return True


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """Log every HTTP request with method, path, status, and duration."""

    async def dispatch(self, request: Request, call_next):
        rid = request.headers.get("X-Request-ID", str(uuid.uuid4())[:8])
        request_id_var.set(rid)
        start = time.perf_counter()
        logger = logging.getLogger("backend.api")

        logger.info("%s %s", request.method, request.url.path)
        try:
            response = await call_next(request)
            elapsed_ms = (time.perf_counter() - start) * 1000
            logger.info(
                "%s %s %d %.1fms",
                request.method,
                request.url.path,
                response.status_code,
                elapsed_ms,
            )
            response.headers["X-Request-ID"] = rid
            return response
        except Exception:
            elapsed_ms = (time.perf_counter() - start) * 1000
            logger.exception("%s %s 500 %.1fms", request.method, request.url.path, elapsed_ms)
            raise


def setup_logging(level: str = "INFO") -> None:
    """Configure structured logging for the backend."""
    fmt = "%(asctime)s [%(levelname)s] [%(request_id)s] %(name)s: %(message)s"
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter(fmt, datefmt="%Y-%m-%dT%H:%M:%S"))
    handler.addFilter(RequestIDFilter())

    root = logging.getLogger("backend")
    root.setLevel(getattr(logging, level.upper(), logging.INFO))
    root.addHandler(handler)
    root.propagate = False
