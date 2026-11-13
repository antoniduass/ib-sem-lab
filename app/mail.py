import smtplib
from email.message import EmailMessage

from flask import current_app


def send_mail(to: str, subject: str, body: str) -> None:
    message = EmailMessage()
    message["From"] = current_app.config["MAIL_SENDER"]
    message["To"] = to
    message["Subject"] = subject
    message.set_content(body)
    with smtplib.SMTP(
        current_app.config["MAIL_SERVER"], current_app.config["MAIL_PORT"], timeout=10
    ) as smtp:
        smtp.send_message(message)
