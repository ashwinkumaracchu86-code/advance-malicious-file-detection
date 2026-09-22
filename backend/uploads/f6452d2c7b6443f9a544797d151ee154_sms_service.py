import logging
import time

from app.core.config import get_settings

settings = get_settings()
logger = logging.getLogger(__name__)

_client = None
_twilio_imported = False


def _get_twilio_client():
    global _client, _twilio_imported
    if _twilio_imported:
        return _client
    _twilio_imported = True
    if settings.TWILIO_ACCOUNT_SID and settings.TWILIO_AUTH_TOKEN:
        try:
            from twilio.rest import Client
            _client = Client(settings.TWILIO_ACCOUNT_SID, settings.TWILIO_AUTH_TOKEN)
            logger.info("Twilio SMS service initialized successfully")
        except Exception as e:
            logger.error("Failed to initialize Twilio client: %s", e)
            _client = None
    return _client


class SMSService:
    _dev_otp_store: dict[str, tuple[str, float]] = {}

    async def send_otp(self, phone_number: str, otp_code: str) -> tuple[bool, str]:
        client = _get_twilio_client()

        if not client:
            SMSService._dev_otp_store[phone_number] = (otp_code, time.time())
            logger.warning(
                "============================== DEV MODE ==============================\n"
                "  SMS not sent - Twilio not configured.\n"
                "  OTP for %s: %s\n"
                "  Code expires in %d minutes.\n"
                "=======================================================================",
                phone_number,
                otp_code,
                settings.OTP_EXPIRE_MINUTES,
            )
            print(
                f"\n{'='*60}\n"
                f"  [DEV MODE] OTP CODE for {phone_number}: {otp_code}\n"
                f"  Expires in {settings.OTP_EXPIRE_MINUTES} minutes\n"
                f"{'='*60}\n"
            )
            return True, f"Development mode - OTP code: {otp_code}"

        try:
            from twilio.base.exceptions import TwilioRestException
            message = client.messages.create(
                body=f"Your verification code is: {otp_code}. It expires in {settings.OTP_EXPIRE_MINUTES} minutes. Do not share this code.",
                from_=settings.TWILIO_PHONE_NUMBER,
                to=phone_number,
            )
            logger.info("SMS sent successfully to %s (SID: %s)", phone_number[-4:], message.sid)
            return True, "OTP sent successfully"

        except Exception as e:
            logger.error("Error sending SMS to %s: %s", phone_number[-4:], str(e))
            error_str = str(e)
            if "21211" in error_str:
                return False, "Invalid phone number"
            elif "21614" in error_str:
                return False, "Phone number is not mobile-capable"
            elif "20003" in error_str:
                return False, "Authentication error with SMS provider"
            elif "20005" in error_str:
                return False, "SMS provider is temporarily unavailable"
            else:
                return False, f"Failed to send OTP: {error_str}"

    def is_configured(self) -> bool:
        return _get_twilio_client() is not None

    @staticmethod
    def get_dev_otp(phone_number: str) -> str | None:
        entry = SMSService._dev_otp_store.get(phone_number)
        if entry and (time.time() - entry[1]) < settings.OTP_EXPIRE_MINUTES * 60:
            return entry[0]
        return None


sms_service = SMSService()
