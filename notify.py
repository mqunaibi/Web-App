# notify.py
# -*- coding: utf-8 -*-
"""
Email notification service for: 'New user approval requested'
- Reads SMTP settings from .env (TLS/SSL)
- To/From from .env; also supports NOTIFY_CC / NOTIFY_BCC
- Optional branding logo via LOGO_URL
- Backward/forward compatible parameter names:
    email/user_email, name/user_name
"""

import os
import logging
import smtplib
from email.message import EmailMessage
from typing import List, Optional, Dict, Any
from dotenv import load_dotenv

load_dotenv()

# SMTP
SMTP_HOST = (os.getenv("SMTP_HOST") or "").strip()
SMTP_PORT = int(os.getenv("SMTP_PORT", "587") or 587)
SMTP_USER = (os.getenv("SMTP_USER") or "").strip()
SMTP_PASSWORD = (os.getenv("SMTP_PASSWORD") or "").strip()
SMTP_USE_TLS = (os.getenv("SMTP_USE_TLS", "1").strip() == "1")
SMTP_USE_SSL = (os.getenv("SMTP_USE_SSL", "0").strip() == "1")

# Addresses
NOTIFY_FROM = (os.getenv("NOTIFY_FROM") or SMTP_USER or "").strip()
DEFAULT_TO = (os.getenv("NOTIFY_TO") or "").strip()

# Branding / Copies
ADMIN_PANEL_URL = (os.getenv("ADMIN_PANEL_URL") or "/newadmin").strip()
LOGO_URL = (os.getenv("LOGO_URL") or "").strip()
NOTIFY_CC_ENV = (os.getenv("NOTIFY_CC") or "").strip()
NOTIFY_BCC_ENV = (os.getenv("NOTIFY_BCC") or "").strip()

def _split_emails(s: str) -> List[str]:
    if not s:
        return []
    # allow comma or semicolon separated, and trim spaces
    return [p.strip() for p in s.replace(";", ",").split(",") if p.strip()]

def _connect_smtp():
    if not SMTP_HOST:
        raise RuntimeError("SMTP_HOST is not configured.")
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
    """Low-level sender used by helpers below."""
    to = to or _split_emails(DEFAULT_TO)
    cc = cc or _split_emails(NOTIFY_CC_ENV)
    bcc = bcc or _split_emails(NOTIFY_BCC_ENV)

    if not to:
        logging.error("Notification failed: no recipients (NOTIFY_TO is empty).")
        return False

    from_addr = (from_addr or NOTIFY_FROM or SMTP_USER).strip()
    if not from_addr:
        logging.error("Notification failed: sender address not set (NOTIFY_FROM/SMTP_USER).")
        return False

    if not text_body:
        # crude fallback: strip tags for text part
        import re
        text_body = re.sub(r"<[^>]+>", "", html_body or "").strip()

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = from_addr
    msg["To"] = ", ".join(to)
    if cc:
        msg["Cc"] = ", ".join(cc)

    msg.set_content(text_body or "")
    msg.add_alternative(html_body or "", subtype="html")

    recipients = list(to) + (cc or []) + (bcc or [])
    try:
        with _connect_smtp() as smtp:
            smtp.send_message(msg, from_addr=from_addr, to_addrs=recipients)
        logging.info("Notification email sent to: %s", recipients)
        return True
    except Exception as e:
        logging.exception("Failed to send email: %s", e)
        return False

def notify_new_user_request(
    # Compatible names
    email: Optional[str] = None,
    user_email: Optional[str] = None,
    name: Optional[str] = None,
    user_name: Optional[str] = None,

    # Optional metadata
    device_name: str = "",
    device_uuid: str = "",
    ip_address: str = "",
    requested_at: Optional[str] = None,
    extra: Optional[Dict[str, Any]] = None,

    # Optional override
    admin_panel_url: Optional[str] = None,
) -> bool:
    """Sends a styled 'New user approval request' email."""
    who_email = (email or user_email or "").strip()
    who_name = (user_name or name or "").strip()
    if not who_email:
        logging.error("notify_new_user_request: missing email/user_email")
        return False

    extra = extra or {}
    device_name = (device_name or extra.get("device_name") or extra.get("device") or "").strip()
    device_uuid = (device_uuid or extra.get("device_uuid") or extra.get("uuid") or "").strip()
    ip_address = (ip_address or extra.get("ip") or "").strip()

    admin_link = (admin_panel_url or ADMIN_PANEL_URL or "/newadmin").strip()

    subject = f"[WE APP] New user approval request: {who_email}"
    brand_dark = "#0d6efd"
    brand_light = "#e9f2ff"

    logo_block = f"""
      <tr>
        <td style="padding:18px 24px 0 24px">
          <img src="{LOGO_URL}" alt="Logo" style="max-width:160px;height:auto;display:block">
        </td>
      </tr>
    """ if LOGO_URL else ""

    # Build detail rows
    details_rows = []
    if who_name:
        details_rows.append(f"<tr><td style='padding:4px 0'><strong>Name:</strong> {who_name}</td></tr>")
    details_rows.append(f"<tr><td style='padding:4px 0'><strong>Email:</strong> {who_email}</td></tr>")
    details_rows.append(f"<tr><td style='padding:4px 0'><strong>Device Name:</strong> {device_name or 'N/A'}</td></tr>")
    details_rows.append(f"<tr><td style='padding:4px 0'><strong>Device UUID:</strong> {device_uuid or 'N/A'}</td></tr>")
    details_rows.append(f"<tr><td style='padding:4px 0'><strong>IP Address:</strong> {ip_address or 'N/A'}</td></tr>")
    if requested_at:
        details_rows.append(f"<tr><td style='padding:4px 0'><strong>Requested At:</strong> {requested_at}</td></tr>")

    # Append extra (ignore keys already displayed)
    for k, v in extra.items():
        if k in {"device_name", "device", "device_uuid", "uuid", "ip"}:
            continue
        details_rows.append(f"<tr><td style='padding:4px 0'><strong>{k}:</strong> {v}</td></tr>")

    html = f"""
    <div style="background:{brand_light};padding:24px 16px;font-family:Arial,Helvetica,sans-serif;">
      <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="max-width:640px;margin:auto;background:#fff;border-radius:14px;box-shadow:0 10px 30px rgba(13,110,253,.08);overflow:hidden">
        {logo_block}
        <tr>
          <td style="padding:20px 24px 0 24px">
            <h2 style="margin:0 0 8px;font-size:20px;color:{brand_dark};letter-spacing:.3px">New user approval request</h2>
            <p style="margin:0;color:#111;font-size:14px;line-height:1.6">
              Below are the details for the new user awaiting approval:
            </p>
          </td>
        </tr>

        <tr>
          <td style="padding:12px 24px">
            <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="font-size:14px;line-height:1.6;color:#111">
              {''.join(details_rows)}
            </table>
          </td>
        </tr>

        <tr>
          <td style="padding:16px 24px 24px 24px">
            <a href="{admin_link}" target="_blank" rel="noopener"
               style="display:inline-block;background:{brand_dark};color:#fff;text-decoration:none;
                      padding:12px 18px;border-radius:999px;font-size:14px">
              Open Admin Panel
            </a>
            <div style="font-size:12px;color:#666;margin-top:10px">
              Or copy & paste: <span style="color:#0a58ca">{admin_link}</span>
            </div>
          </td>
        </tr>

        <tr>
          <td style="padding:14px 24px;border-top:1px solid #eef2f7;color:#666;font-size:12px">
            This message was generated automatically by WE APP.
          </td>
        </tr>
      </table>
    </div>
    """

    return send_email(subject=subject, html_body=html)
