import smtplib
import random
import string
from email.message import EmailMessage

SENDER_EMAIL = "trustshieldhelp@gmail.com"
SENDER_PASSWORD = "aokg jupw ehrb vcha"


def generate_code(length=5):
    return ''.join(random.choices(string.digits, k=length))

def send_verification_email(recipient_email, code, action):
    try:
        msg = EmailMessage()
        msg.set_content(f"""
            Hi, 

            Your TrustShield verification code is:

                {code}

            Please enter this code to continue.

            If you did not request to {action}, please ignore this email.

            – TrustShield Security Team
            """)
        
        msg["Subject"] = "Your TrustShield Verification Code"
        msg["From"] = SENDER_EMAIL
        msg["To"] = recipient_email

        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as smtp:
            smtp.login(SENDER_EMAIL, SENDER_PASSWORD)
            smtp.send_message(msg)

        return True, "Verification code sent."
    except Exception as e:
        return False, str(e)
