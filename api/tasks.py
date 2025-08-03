from celery import shared_task


@shared_task(bind=True)
def send_email(self, email):
    email.send()
    return f'Email sent to {email}'


@shared_task(bind=True)
def send_phone(self, api, params):
    api.send_sms(params)
    return f'Phone sent'
