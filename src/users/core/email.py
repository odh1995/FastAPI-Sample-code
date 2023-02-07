from typing import List
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication
import smtplib
from pydantic import EmailStr
from src.users.domain.models.user import User
from src.users.core.config import settings
from jinja2 import Environment, select_autoescape, PackageLoader
import ssl


env = Environment(
    loader=PackageLoader('src.main', 'templates'),
    autoescape=select_autoescape(['html', 'xml'])
)


class Email:
    def __init__(self, user: User, email: str, url: str = ''):
        self.name = user.name
        self.sender = 'Codevo <admin@admin.com>'
        self.email = email
        self.url = url
        pass

    async def sendMail(self, subject, template):

        sender_email = settings.EMAIL_FROM
        receiver_email = self.email

        # Generate the HTML template base on the template name
        template = env.get_template(f'{template}.html')

        html = template.render(
            url=self.url,
            first_name=self.name,
            subject=subject
        )

        msg = MIMEMultipart()
        msg['Subject'] = subject
        msg['From'] = sender_email
        msg['To'] = receiver_email
        context = ssl.create_default_context()

        msgText = MIMEText('<b>%s</b>' % (html), 'html')
        msg.attach(msgText)

        try:
            with smtplib.SMTP_SSL(settings.EMAIL_HOST, settings.EMAIL_PORT, context=context) as s:
                s.login(settings.EMAIL_USERNAME, settings.EMAIL_PASSWORD)
                s.send_message(msg)

        except Exception as e:
            print(e)

    async def sendVerificationCode(self):
        await self.sendMail('Your verification code (Valid for 10min)', 'verification')

    async def sendResetPassword(self):
        await self.sendMail('Please reset your password', 'reset_password')
