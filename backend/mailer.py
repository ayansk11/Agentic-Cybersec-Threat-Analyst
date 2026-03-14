"""Async email sending via SMTP with console fallback."""

import logging
from email.message import EmailMessage

import aiosmtplib

from backend.config import get_settings

logger = logging.getLogger("backend.email")


def _is_configured() -> bool:
    """Return True if SMTP is configured."""
    settings = get_settings()
    return bool(settings.smtp_host)


async def send_email(to: str, subject: str, body_html: str) -> bool:
    """Send an email. Returns True if sent, False if SMTP not configured (logged instead)."""
    settings = get_settings()

    if not settings.smtp_host:
        logger.info("SMTP not configured — email to %s not sent (subject: %s)", to, subject)
        return False

    msg = EmailMessage()
    msg["From"] = f"{settings.smtp_from_name} <{settings.smtp_from_email}>"
    msg["To"] = to
    msg["Subject"] = subject
    msg.set_content(body_html, subtype="html")

    try:
        await aiosmtplib.send(
            msg,
            hostname=settings.smtp_host,
            port=settings.smtp_port,
            username=settings.smtp_user or None,
            password=settings.smtp_password or None,
            use_tls=settings.smtp_use_tls,
        )
        logger.info("Email sent to %s: %s", to, subject)
        return True
    except Exception:
        logger.warning("Failed to send email to %s", to, exc_info=True)
        return False


async def send_verification_email(to: str, token: str, frontend_url: str) -> bool:
    """Send an email verification link."""
    verify_url = f"{frontend_url}?verify_token={token}"
    html = f"""\
<h2>Verify your email</h2>
<p>Click the link below to verify your email address:</p>
<p><a href="{verify_url}">{verify_url}</a></p>
<p>This link expires in 24 hours.</p>
<p style="color:#666;font-size:12px">If you didn't create an account, ignore this email.</p>
"""
    sent = await send_email(to, "Verify your email — ThreatAnalyst", html)
    if not sent:
        logger.info("Verification token for %s: %s (SMTP not configured)", to, token)
    return sent


async def send_password_reset_email(to: str, token: str, frontend_url: str) -> bool:
    """Send a password reset link."""
    reset_url = f"{frontend_url}?reset_token={token}"
    html = f"""\
<h2>Reset your password</h2>
<p>Click the link below to reset your password:</p>
<p><a href="{reset_url}">{reset_url}</a></p>
<p>This link expires in 1 hour.</p>
<p style="color:#666;font-size:12px">If you didn't request a password reset, ignore this email.</p>
"""
    sent = await send_email(to, "Password reset — ThreatAnalyst", html)
    if not sent:
        logger.info("Password reset token for %s: %s (SMTP not configured)", to, token)
    return sent
