# mailer.py
# -*- coding: utf-8 -*-

import os
import logging
import smtplib
from email.message import EmailMessage
from typing import List, Optional
from dotenv import load_dotenv

load_dotenv()

SMTP_HOST = os.getenv("SMTP_HOST", "").strip()
SMTP_PORT = int(os.getenv("SMTP_PORT", "587").strip() or 587)
SMTP_USER = os.getenv("SMTP_USER", "").strip()
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "").strip()
SMTP_USE_TLS = (os.getenv("SMTP_USE_TLS", "1").strip() == "1")
SMTP_USE_SSL = (os.getenv("SMTP_USE_SSL", "0").strip() == "1")

NOTIFY_FROM = (os.getenv("NOTIFY_FROM") or os.getenv("SMTP_USER") or "").strip()
DEFAULT_TO = os.getenv("NOTIFY_TO", "").strip()

def _split_emails(s: str) -> List[str]:
    if not s:
        return []
    # allow comma or semicolon separated
    parts = [p.strip() for p in s.replace(";", ",").split(",")]
    return [p for p in parts if p]

def _connect_smtp():
    """
    Returns a ready-to-use SMTP connection based on TLS/SSL flags.
    """
    if SMTP_USE_SSL:
        server = smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, timeout=30)
    else:
        server = smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=30)
        if SMTP_USE_TLS:
            server.starttls()
    if SMTP_USER:
        server.login(SMTP_USER, SMTP_PASSWORD)
    return server

def send_email(
    subject: str,
    html_body: str,
    text_body: Optional[str] = None,
    to: Optional[List[str]] = None,
    cc: Optional[List[str]] = None,
    bcc: Optional[List[str]] = None,
    from_addr: Optional[str] = None,
) -> bool:
    """
    Generic sender. Returns True on success, False on failure.
    """
    if not to:
        to = _split_emails(DEFAULT_TO)

    if not to:
        logging.error("No recipients defined for notification email.")
        return False

    from_addr = (from_addr or NOTIFY_FROM or SMTP_USER).strip()
    if not from_addr:
        logging.error("No NOTIFY_FROM/SMTP_USER configured for sender address.")
        return False

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = from_addr
    msg["To"] = ", ".join(to)
    if cc:
        msg["Cc"] = ", ".join(cc)

    if not text_body:
        # Simple fallback: strip HTML tags crudely if needed
        import re
        text_body = re.sub(r"<[^>]+>", "", html_body or "").strip()

    msg.set_content(text_body or "")
    msg.add_alternative(html_body or "", subtype="html")

    # Full recipients = To + Cc + Bcc
    rcpts = list(to)
    if cc:
        rcpts.extend(cc)
    if bcc:
        rcpts.extend(bcc)

    try:
        with _connect_smtp() as smtp:
            smtp.send_message(msg, from_addr=from_addr, to_addrs=rcpts)
        logging.info("Notification email sent to: %s", rcpts)
        return True
    except Exception as e:
        logging.exception("Failed to send email: %s", e)
        return False


def notify_new_user_request(
    email: str,
    device_name: str = "",
    device_uuid: str = "",
    ip_address: str = "",
    extra: Optional[dict] = None,
    admin_panel_url: Optional[str] = None,
) -> bool:
    """
    Helper for the exact use-case: 'New user approval requested'.
    """
    extra = extra or {}
    admin_link = admin_panel_url or "/newadmin"

    title = "New user approval request"
    subject = f"[WE APP] {title}: {email}"

    html = f"""
    <div style="font-family:Arial,Helvetica,sans-serif;font-size:14px;line-height:1.6">
      <h2 style="margin:0 0 10px">{title}</h2>
      <p><strong>Email:</strong> {email}</p>
      <p><strong>Device Name:</strong> {device_name or "N/A"}<br>
         <strong>Device UUID:</strong> {device_uuid or "N/A"}<br>
         <strong>IP Address:</strong> {ip_address or "N/A"}</p>
      {"".join([f"<p><strong>{k}:</strong> {v}</p>" for k,v in extra.items()])}
      <p style="margin-top:16px">
        Review/approve from Admin Panel:
        <a href="{admin_link}" target="_blank" rel="noopener">{admin_link}</a>
      </p>
      <hr>
      <p style="color:#666">This message was generated automatically.</p>
    </div>
    """

    return send_email(subject=subject, html_body=html)
