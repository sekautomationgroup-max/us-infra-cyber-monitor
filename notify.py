"""
Delivery layer: email (Gmail SMTP) and SMS (carrier email-to-text gateway or
Twilio). All credentials come from environment variables, which GitHub Actions
populates from repository Secrets.

Environment variables
---------------------
GMAIL_ADDRESS        Gmail account that sends the alerts
GMAIL_APP_PASSWORD   16-character Gmail App Password (not your login password)
ALERT_EMAIL_TO       Where alert emails go (comma-separated allowed)
ALERT_SMS_TO         Carrier gateway address, e.g. 5551234567@vtext.com
                     (comma-separated allowed). Leave unset to disable texts.

SMS_PROVIDER         "email" (default) or "twilio"
TWILIO_ACCOUNT_SID   Only used when SMS_PROVIDER=twilio
TWILIO_AUTH_TOKEN
TWILIO_FROM          Your Twilio number, E.164 (+15551234567)
TWILIO_TO            Destination number(s), E.164, comma-separated

DRY_RUN              "1" prints messages instead of sending them.
"""

from __future__ import annotations

import logging
import os
import smtplib
import ssl
from email.message import EmailMessage
from typing import Iterable

log = logging.getLogger("notify")

SMS_MAX_CHARS = 150  # carrier gateways truncate or split above ~160


def _env(name: str, default: str = "") -> str:
    return os.environ.get(name, default).strip()


def _split(value: str) -> list[str]:
    return [v.strip() for v in value.split(",") if v.strip()]


def dry_run() -> bool:
    return _env("DRY_RUN") == "1"


def email_configured() -> bool:
    return bool(_env("GMAIL_ADDRESS") and _env("GMAIL_APP_PASSWORD") and _env("ALERT_EMAIL_TO"))


def sms_configured() -> bool:
    provider = _env("SMS_PROVIDER", "email").lower()
    if provider == "twilio":
        return all(_env(k) for k in ("TWILIO_ACCOUNT_SID", "TWILIO_AUTH_TOKEN", "TWILIO_FROM", "TWILIO_TO"))
    return bool(_env("ALERT_SMS_TO")) and bool(_env("GMAIL_ADDRESS") and _env("GMAIL_APP_PASSWORD"))


# ---------------------------------------------------------------------------
# Email
# ---------------------------------------------------------------------------

def _send_gmail(to_addrs: Iterable[str], subject: str, body: str, html: str | None = None) -> bool:
    to_list = list(to_addrs)
    if dry_run():
        print("\n" + "=" * 70)
        print(f"[DRY RUN] EMAIL to {', '.join(to_list) or '(no recipient configured)'}")
        print(f"Subject: {subject}")
        print("-" * 70)
        print(body)
        print("=" * 70)
        return True
    sender = _env("GMAIL_ADDRESS")
    password = _env("GMAIL_APP_PASSWORD")
    if not to_list or not sender or not password:
        log.info("Email not configured; skipping '%s'", subject)
        return False

    msg = EmailMessage()
    msg["From"] = sender
    msg["To"] = ", ".join(to_list)
    msg["Subject"] = subject
    msg.set_content(body)
    if html:
        msg.add_alternative(html, subtype="html")

    context = ssl.create_default_context()
    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465, context=context, timeout=30) as server:
            server.login(sender, password)
            server.send_message(msg)
        log.info("Email sent: %s -> %s", subject, to_list)
        return True
    except Exception as exc:  # noqa: BLE001
        log.error("Email send failed (%s): %s", subject, exc)
        return False


def send_email(subject: str, body: str, html: str | None = None) -> bool:
    return _send_gmail(_split(_env("ALERT_EMAIL_TO")), subject, body, html)


# ---------------------------------------------------------------------------
# SMS
# ---------------------------------------------------------------------------

def _send_sms_via_gateway(text: str) -> bool:
    """Carrier email-to-text. Subject is left empty on purpose: most gateways
    prepend the subject to the message and it wastes characters."""
    return _send_gmail(_split(_env("ALERT_SMS_TO")), "", text)


def _send_sms_via_twilio(text: str) -> bool:
    """Twilio REST API using only the standard library (no SDK needed)."""
    import base64
    import json
    import urllib.parse
    import urllib.request

    sid = _env("TWILIO_ACCOUNT_SID")
    token = _env("TWILIO_AUTH_TOKEN")
    from_num = _env("TWILIO_FROM")
    ok = True
    for to_num in _split(_env("TWILIO_TO")):
        if dry_run():
            print(f"[DRY RUN] TWILIO SMS {from_num} -> {to_num}: {text}")
            continue
        url = f"https://api.twilio.com/2010-04-01/Accounts/{sid}/Messages.json"
        data = urllib.parse.urlencode({"From": from_num, "To": to_num, "Body": text}).encode()
        req = urllib.request.Request(url, data=data, method="POST")
        auth = base64.b64encode(f"{sid}:{token}".encode()).decode()
        req.add_header("Authorization", f"Basic {auth}")
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                payload = json.loads(resp.read().decode())
                log.info("Twilio SMS queued sid=%s to=%s", payload.get("sid"), to_num)
        except Exception as exc:  # noqa: BLE001
            log.error("Twilio send failed to %s: %s", to_num, exc)
            ok = False
    return ok


def send_sms(text: str) -> bool:
    text = text if len(text) <= SMS_MAX_CHARS else text[: SMS_MAX_CHARS - 1] + "…"
    provider = _env("SMS_PROVIDER", "email").lower()
    if provider == "twilio":
        return _send_sms_via_twilio(text)
    if dry_run():
        print(f"[DRY RUN] SMS ({len(text)} chars) -> {_env('ALERT_SMS_TO') or '(no gateway configured)'}: {text}")
        return True
    if not _env("ALERT_SMS_TO"):
        log.info("ALERT_SMS_TO not set; skipping SMS")
        return False
    return _send_sms_via_gateway(text)
