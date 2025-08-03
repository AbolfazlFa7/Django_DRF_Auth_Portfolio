from django.core.mail import EmailMultiAlternatives
from django.template.loader import render_to_string
from api.tasks import send_email
from django.conf import settings


def send_verification_code(email, code):
    email = EmailMultiAlternatives(
        subject='Verify Your Email',
        body=render_to_string('email/send_totp.html', {'code': code}),
        from_email=settings.EMAIL_HOST_USER,
        to=[email],
    )
    email.content_subtype = 'html'
    send_email.delay(email)
