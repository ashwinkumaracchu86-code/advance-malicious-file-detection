import logging
import smtplib
import ssl
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from app.core.config import get_settings

settings = get_settings()
logger = logging.getLogger(__name__)

EMAIL_SMTP_MAP = {
    "gmail.com": ("smtp.gmail.com", 587),
    "googlemail.com": ("smtp.gmail.com", 587),
    "outlook.com": ("smtp.office365.com", 587),
    "hotmail.com": ("smtp.office365.com", 587),
    "live.com": ("smtp.office365.com", 587),
    "yahoo.com": ("smtp.mail.yahoo.com", 587),
    "yahoo.co.in": ("smtp.mail.yahoo.com", 587),
    "icloud.com": ("smtp.mail.me.com", 587),
    "me.com": ("smtp.mail.me.com", 587),
    "aol.com": ("smtp.aol.com", 587),
    "zoho.com": ("smtp.zoho.com", 587),
    "zohomail.com": ("smtp.zoho.com", 587),
    "protonmail.com": ("smtp.protonmail.ch", 587),
    "proton.me": ("smtp.protonmail.ch", 587),
    "gmx.com": ("smtp.gmx.com", 587),
    "mail.com": ("smtp.mail.com", 587),
    "rediffmail.com": ("smtp.rediffmail.com", 465),
    "yandex.com": ("smtp.yandex.com", 465),
    "rambler.ru": ("smtp.rambler.ru", 465),
}


def detect_smtp(email: str) -> tuple[str, int]:
    domain = email.split("@")[-1].lower().strip()
    if domain in EMAIL_SMTP_MAP:
        return EMAIL_SMTP_MAP[domain]
    return ("smtp.mail.yahoo.com", 587)


class EmailService:
    def __init__(self):
        self.smtp_server = settings.SMTP_SERVER
        self.smtp_port = settings.SMTP_PORT
        self.smtp_username = settings.SMTP_USERNAME
        self.smtp_password = settings.SMTP_PASSWORD
        self.from_email = settings.SMTP_FROM_EMAIL or self.smtp_username
        self.from_name = settings.SMTP_FROM_NAME or settings.APP_NAME
        self.enabled = bool(self.smtp_username and self.smtp_password)

    async def send_otp(self, to_email: str, otp_code: str, user_name: str = "") -> tuple[bool, str]:
        if not self.enabled:
            logger.warning(
                "Email not configured. OTP for %s: %s", to_email, otp_code
            )
            print(
                f"\n{'='*60}\n"
                f"  [DEV MODE] OTP EMAIL for {to_email}\n"
                f"  Code: {otp_code}\n"
                f"  Expires in {settings.OTP_EXPIRE_MINUTES} minutes\n"
                f"{'='*60}\n"
            )
            return True, f"Development mode - OTP code: {otp_code}"

        try:
            msg = MIMEMultipart("alternative")
            msg["Subject"] = f"Your Verification Code - {settings.APP_NAME}"
            msg["From"] = f"{self.from_name} <{self.from_email}>"
            msg["To"] = to_email
            msg["X-Mailer"] = "Secure2FA"

            display_name = user_name or "User"

            html_body = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
            </head>
            <body style="margin:0;padding:0;background-color:#0f172a;font-family:'Segoe UI',Tahoma,Geneva,Verdana,sans-serif;">
                <table width="100%" cellpadding="0" cellspacing="0" style="background-color:#0f172a;padding:40px 20px;">
                    <tr>
                        <td align="center">
                            <table width="500" cellpadding="0" cellspacing="0" style="background-color:#1e293b;border-radius:16px;border:1px solid #334155;overflow:hidden;">
                                <tr>
                                    <td style="background:linear-gradient(135deg,#0891b2,#06b6d4);padding:30px;text-align:center;">
                                        <h1 style="color:#ffffff;margin:0;font-size:24px;">&#128274; Secure 2FA</h1>
                                        <p style="color:#cffafe;margin:8px 0 0;font-size:14px;">Two-Factor Authentication</p>
                                    </td>
                                </tr>
                                <tr>
                                    <td style="padding:40px 30px;">
                                        <p style="color:#e2e8f0;font-size:16px;margin:0 0 8px;">Hello {display_name},</p>
                                        <p style="color:#94a3b8;font-size:14px;margin:0 0 24px;">Your verification code is:</p>

                                        <div style="background-color:#0f172a;border:2px dashed #06b6d4;border-radius:12px;padding:20px;text-align:center;margin:0 0 24px;">
                                            <span style="color:#22d3ee;font-size:36px;font-weight:bold;letter-spacing:8px;font-family:'Courier New',monospace;">{otp_code}</span>
                                        </div>

                                        <p style="color:#94a3b8;font-size:13px;margin:0 0 8px;">&#9200; This code expires in <strong style="color:#f59e0b;">{settings.OTP_EXPIRE_MINUTES} minutes</strong></p>
                                        <p style="color:#94a3b8;font-size:13px;margin:0 0 24px;">&#128683; Do not share this code with anyone</p>

                                        <div style="border-top:1px solid #334155;padding-top:20px;">
                                            <p style="color:#64748b;font-size:12px;margin:0;">If you didn't request this code, please ignore this email or contact support.</p>
                                        </div>
                                    </td>
                                </tr>
                                <tr>
                                    <td style="background-color:#0f172a;padding:16px 30px;text-align:center;border-top:1px solid #1e293b;">
                                        <p style="color:#475569;font-size:11px;margin:0;">{settings.APP_NAME} &copy; 2026 | Secure Authentication System</p>
                                    </td>
                                </tr>
                            </table>
                        </td>
                    </tr>
                </table>
            </body>
            </html>
            """

            text_body = f"""
            {settings.APP_NAME} - Verification Code

            Hello {display_name},

            Your verification code is: {otp_code}

            This code expires in {settings.OTP_EXPIRE_MINUTES} minutes.
            Do not share this code with anyone.

            If you didn't request this code, please ignore this email.
            """

            msg.attach(MIMEText(text_body, "plain"))
            msg.attach(MIMEText(html_body, "html"))

            smtp_server = self.smtp_server
            smtp_port = self.smtp_port

            if not smtp_server or smtp_server == "smtp.gmail.com":
                detected_server, detected_port = detect_smtp(self.from_email)
                smtp_server = detected_server
                smtp_port = detected_port

            logger.info("Connecting to %s:%s for %s", smtp_server, smtp_port, self.from_email)

            context = ssl.create_default_context()

            if smtp_port == 465:
                with smtplib.SMTP_SSL(smtp_server, smtp_port, timeout=15, context=context) as server:
                    server.login(self.smtp_username, self.smtp_password)
                    server.sendmail(self.from_email, to_email, msg.as_string())
            else:
                with smtplib.SMTP(smtp_server, smtp_port, timeout=15) as server:
                    server.ehlo()
                    server.starttls(context=context)
                    server.ehlo()
                    server.login(self.smtp_username, self.smtp_password)
                    server.sendmail(self.from_email, to_email, msg.as_string())

            logger.info("OTP email sent to %s via %s", to_email, smtp_server)
            return True, "OTP sent to your email"

        except smtplib.SMTPAuthenticationError:
            logger.error("SMTP auth failed for %s. Use an App Password, not your regular password.", self.smtp_username)
            return False, "Email authentication failed. Use an App Password (not your regular password)."
        except smtplib.SMTPConnectError:
            logger.error("Could not connect to %s:%s", smtp_server, smtp_port)
            return False, "Could not connect to email server. Check SMTP settings."
        except smtplib.SMTPServerDisconnected:
            logger.error("SMTP server disconnected for %s", to_email)
            return False, "Email server disconnected. Try again."
        except smtplib.SMTPException as e:
            logger.error("SMTP error sending to %s: %s", to_email, str(e))
            return False, f"Failed to send email: {str(e)}"
        except ssl.SSLError as e:
            logger.error("SSL error: %s", str(e))
            return False, "SSL connection error. Check SMTP port settings."
        except Exception as e:
            logger.error("Error sending email to %s: %s", to_email, str(e))
            return False, f"Failed to send email: {str(e)}"

    def is_configured(self) -> bool:
        return self.enabled


email_service = EmailService()
