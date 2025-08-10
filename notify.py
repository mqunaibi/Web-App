# notify.py
# -*- coding: utf-8 -*-
"""
Lightweight email notifications.

Reads SMTP settings from environment variables:
  SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASSWORD,
  SMTP_USE_TLS, SMTP_USE_SSL, NOTIFY_TO, NOTIFY_FROM

Exposes:
  - notify_new_user_request(user_email, user_name="", requested_at=None, extra=None) -> bool
"""

import os
import smtplib
import logging
from email.mime.text import MIMEText
from email.utils import formataddr, make_msgid
from email.header import Header
from datetime import datetime


def _get_bool(name: str, default: bool = False) -> bool:
    val = (os.getenv(name, "").strip() or "").lower()
    if val in ("1", "true", "yes", "y", "on"):
        return True
    if val in ("0", "false", "no", "n", "off"):
        return False
    return default


def _smtp_config():
    return {
        "host": os.getenv("SMTP_HOST", "").strip(),
        "port": int(os.getenv("SMTP_PORT", "587")),
        "user": os.getenv("SMTP_USER", "").strip(),
        "password": os.getenv("SMTP_PASSWORD", "").strip(),
        "use_tls": _get_bool("SMTP_USE_TLS", True),
        "use_ssl": _get_bool("SMTP_USE_SSL", False),
        "notify_to": [e.strip() for e in os.getenv("NOTIFY_TO", "").split(",") if e.strip()],
        "notify_from": os.getenv("NOTIFY_FROM", os.getenv("SMTP_USER", "no-reply@localhost")),
    }


def _send_email(subject: str, body: str, to_list: list) -> bool:
    cfg = _smtp_config()
    if not cfg["host"] or not to_list:
        logging.warning("[notify] Missing SMTP_HOST or recipients.")
        return False

    msg = MIMEText(body, _charset="utf-8")
    try:
        msg["Subject"] = str(Header(subject, "utf-8"))
    except Exception:
        msg["Subject"] = subject

    sender = cfg["notify_from"]
    msg["From"] = formataddr((sender, sender)) if "<" not in sender else sender
    msg["To"] = ", ".join(to_list)
    msg["Message-ID"] = make_msgid()

    try:
        if cfg["use_ssl"]:
            # SSL connection with context manager and timeout
            with smtplib.SMTP_SSL(cfg["host"], cfg["port"], timeout=15) as server:
                server.ehlo()
                if cfg["user"]:
                    server.login(cfg["user"], cfg["password"])
                server.sendmail(sender, to_list, msg.as_string())
        else:
            # STARTTLS (if enabled) with context manager and timeout
            with smtplib.SMTP(cfg["host"], cfg["port"], timeout=15) as server:
                server.ehlo()
                if cfg["use_tls"]:
                    server.starttls()
                    server.ehlo()
                if cfg["user"]:
                    server.login(cfg["user"], cfg["password"])
                server.sendmail(sender, to_list, msg.as_string())
        return True
    except Exception as e:
        logging.warning("[notify] Email send failed: %s", e)
        return False


def notify_new_user_request(
    user_email: str,
    user_name: str = "",
    requested_at: str = None,
    extra: dict = None
) -> bool:
    """
    Sends an email notification about a new user approval request.
    Returns True on success, False otherwise.
    """
    cfg = _smtp_config()
    to_list = cfg["notify_to"]
    if not to_list:
        logging.warning("[notify] NOTIFY_TO is empty; skipping.")
        return False

    ts = requested_at or datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

    subject = "[WE-APP] New user approval requested"
    lines = [
        "A new user approval has been requested:",
        f"Name:  {user_name or '(not provided)'}",
        f"Email: {user_email}",
        f"Requested at: {ts}",
    ]
    if extra:
        lines.append("---- Extra ----")
        for k, v in extra.items():
            lines.append(f"{k}: {v}")

    lines.append("")
    lines.append("Actions: Please review in Admin Panel (Approve / Reject)")

    body = "\n".join(lines)
    return _send_email(subject, body, to_list)
