"""
Minimal SMTP email sender, used for password-reset notifications.
"""

from __future__ import annotations

import smtplib
from email.message import EmailMessage

from app.logging_config import get_logger

from .config import settings

logger = get_logger(__name__)


def is_email_configured() -> bool:
    return bool(settings.smtp_host and settings.smtp_username and settings.smtp_password)


def send_email(*, to: str, subject: str, body: str) -> bool:
    if not is_email_configured():
        logger.warning("SMTP not configured; skipping email send to %s", to)
        return False

    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = settings.smtp_from
    message["To"] = to
    message.set_content(body)

    try:
        with smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=10) as server:
            if settings.smtp_use_tls:
                server.starttls()
            server.login(settings.smtp_username, settings.smtp_password)
            server.send_message(message)
        return True
    except Exception:
        logger.exception("Failed to send email to %s", to)
        return False


def send_password_reset_email(*, to: str, username: str, reset_url: str, ttl_minutes: int) -> bool:
    subject = "Ataraxia SOC — Password reset request"
    body = (
        f"Hi {username},\n\n"
        f"A password reset was requested for your Ataraxia SOC account.\n\n"
        f"Reset your password using the link below. This link expires in "
        f"{ttl_minutes} minutes and can only be used once.\n\n"
        f"{reset_url}\n\n"
        "If you didn't request this, you can safely ignore this email — "
        "your password will not be changed.\n"
    )
    return send_email(to=to, subject=subject, body=body)
