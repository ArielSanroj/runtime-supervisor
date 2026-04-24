"""Email delivery via Resend.

Single template for now (magic link). If RESEND_API_KEY is unset we log
the email to stdout so dev/local always works without external creds.
"""
from __future__ import annotations

import logging

import resend

from .config import get_settings

log = logging.getLogger(__name__)


def send_magic_link(to_email: str, link_url: str) -> None:
    """Email a passwordless login link. No-op (logs only) when RESEND_API_KEY missing."""
    settings = get_settings()

    subject = "Tu acceso a vibefixing"
    text_body = (
        f"Para entrar al dashboard de vibefixing, abrí este link:\n\n"
        f"{link_url}\n\n"
        f"El link sirve una sola vez y expira en 15 minutos.\n\n"
        f"Si no pediste este acceso, ignorá este mensaje."
    )
    html_body = f"""\
<!doctype html>
<html><body style="font-family:system-ui,-apple-system,sans-serif;color:#111;max-width:520px;margin:32px auto;padding:24px;line-height:1.6;">
  <h1 style="font-size:20px;margin:0 0 16px;">Tu acceso a vibefixing</h1>
  <p>Para entrar al dashboard, abrí este link:</p>
  <p style="margin:24px 0;">
    <a href="{link_url}" style="display:inline-block;background:#10b981;color:#000;font-weight:600;padding:12px 20px;border-radius:8px;text-decoration:none;">
      Abrir dashboard →
    </a>
  </p>
  <p style="color:#666;font-size:13px;">
    Si el botón no funciona, copiá este URL en tu navegador:<br>
    <code style="word-break:break-all;">{link_url}</code>
  </p>
  <p style="color:#999;font-size:12px;margin-top:24px;">
    El link sirve una sola vez y expira en 15 minutos. Si no pediste acceso, ignorá este mensaje.
  </p>
</body></html>
"""

    if not settings.email_enabled:
        log.warning(
            "RESEND_API_KEY unset — magic link not sent. Would send to %s with link %s",
            to_email,
            link_url,
        )
        return

    resend.api_key = settings.resend_api_key
    try:
        resend.Emails.send({
            "from": settings.resend_from,
            "to": [to_email],
            "subject": subject,
            "text": text_body,
            "html": html_body,
        })
    except Exception as e:  # pragma: no cover — third-party failure
        log.exception("Resend send failed for %s: %s", to_email, e)
        raise
