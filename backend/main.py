"""FastAPI application entry point."""

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from prometheus_fastapi_instrumentator import Instrumentator
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from backend.api.rate_limit import limiter
from backend.api.routes import router
from backend.config import get_settings
from backend.db import init_db
from backend.logging_config import RequestLoggingMiddleware, setup_logging

settings = get_settings()
setup_logging(settings.log_level)
logger = logging.getLogger("backend")


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    logger.info("Application started")
    yield
    logger.info("Shutting down gracefully...")


app = FastAPI(
    title="Cybersecurity Threat Analyst API",
    description="Multi-agent threat analysis with MITRE ATT&CK RAG",
    version="0.1.0",
    lifespan=lifespan,
)

# Rate limiting
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# CORS
origins = [o.strip() for o in settings.cors_origins.split(",") if o.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Request logging
app.add_middleware(RequestLoggingMiddleware)

# Prometheus metrics
Instrumentator(
    excluded_handlers=["/metrics", "/", "/docs", "/openapi.json"],
).instrument(app).expose(app, endpoint="/metrics", include_in_schema=False)

app.include_router(router)

from backend.api.auth_routes import auth_router  # noqa: E402

app.include_router(auth_router)


@app.get("/")
async def root():
    return {"message": "Cybersecurity Threat Analyst API", "docs": "/docs"}
