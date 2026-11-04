"""Sends SMS. "console" (development) logs the message; "twilio" sends it through Twilio's REST API."""

import logging
import re

import httpx

from app.config import get_settings

log = logging.getLogger("capstoneconnect.sms")
# A reset code in a message (4 to 8 digits on their own).
CODE = re.compile(r"\b\d{4,8}\b")


class SmsError(Exception):
    pass


def send_sms(to_e164: str, body: str) -> None:
    settings = get_settings()
    if settings.sms_provider == "twilio":
        _send_twilio(to_e164, body)
        return
    # Development: the message goes to the server log instead of a phone. The code itself is only
    # written there with ALLOW_DEV_CODE=true (a laptop); otherwise it is masked, as is the number.
    if settings.allow_dev_code:
        log.warning("SMS to %s: %s", to_e164, body)
    else:
        log.warning("SMS to %s: %s", mask_number(to_e164), CODE.sub("••••••", body))


def mask_number(e164: str) -> str:
    return f"{e164[:3]}•••••{e164[-3:]}" if len(e164) > 6 else "•••"


def _send_twilio(to_e164: str, body: str) -> None:
    s = get_settings()
    if not (s.twilio_account_sid and s.twilio_auth_token and s.twilio_from_number):
        raise SmsError("Twilio is selected but TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN or TWILIO_FROM_NUMBER is missing")
    try:
        response = httpx.post(
            f"https://api.twilio.com/2010-04-01/Accounts/{s.twilio_account_sid}/Messages.json",
            data={"To": to_e164, "From": s.twilio_from_number, "Body": body},
            auth=(s.twilio_account_sid, s.twilio_auth_token),
            timeout=15,
        )
    except httpx.HTTPError as exc:
        raise SmsError(str(exc)) from exc
    if response.status_code >= 300:
        raise SmsError(f"Twilio answered {response.status_code}: {response.text[:200]}")
