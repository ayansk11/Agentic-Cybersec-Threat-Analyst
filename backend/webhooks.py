"""Webhook notifications for high-severity analysis results."""

import asyncio
import logging

import httpx

from backend.config import get_settings
from backend.security import validate_webhook_url

logger = logging.getLogger("backend.webhooks")

SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0}


def _meets_threshold(severity: str, threshold: str) -> bool:
    sev = severity.upper().split()[0] if severity else "UNKNOWN"
    return SEVERITY_ORDER.get(sev, 0) >= SEVERITY_ORDER.get(threshold.upper(), 3)


async def _get_webhook_config() -> tuple[str, str]:
    """Return (webhook_url, severity_threshold), checking DB first then env."""
    try:
        from backend.db_users import get_app_settings_bulk

        db_settings = await get_app_settings_bulk(["webhook_url", "webhook_severity_threshold"])
        url = db_settings.get("webhook_url", "")
        threshold = db_settings.get("webhook_severity_threshold", "")
    except Exception:
        url, threshold = "", ""

    # Fall back to env vars if DB values are empty
    settings = get_settings()
    if not url:
        url = settings.webhook_url
    if not threshold:
        threshold = settings.webhook_severity_threshold
    return url, threshold


async def send_webhook(cve_id: str, severity: str, summary: str, techniques: list[dict]) -> None:
    """POST analysis summary to the configured webhook URL."""
    url, threshold = await _get_webhook_config()
    if not url:
        return
    if not _meets_threshold(severity, threshold):
        return

    # SSRF prevention: validate webhook URL targets a public host
    try:
        validate_webhook_url(url)
    except ValueError as e:
        logger.warning("Webhook URL blocked (SSRF prevention): %s — %s", url, e)
        return

    payload = {
        "event": "analysis_complete",
        "cve_id": cve_id,
        "severity": severity,
        "summary": summary,
        "techniques": [
            {"id": t.get("technique_id"), "name": t.get("name")} for t in techniques[:10]
        ],
    }
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            await client.post(url, json=payload)
        logger.info("Webhook sent for %s (severity: %s)", cve_id, severity)
    except Exception:
        logger.warning("Webhook delivery failed for %s", cve_id, exc_info=True)


def fire_webhook(cve_id: str, severity: str, summary: str, techniques: list[dict]) -> None:
    """Fire-and-forget webhook (non-blocking)."""
    try:
        loop = asyncio.get_running_loop()
        loop.create_task(send_webhook(cve_id, severity, summary, techniques))
    except RuntimeError:
        asyncio.run(send_webhook(cve_id, severity, summary, techniques))
