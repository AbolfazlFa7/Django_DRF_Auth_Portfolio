from kavenegar import KavenegarAPI
from django.conf import settings
from api.tasks import send_phone


def send_verification_code(phone, code):
    try:
        api = KavenegarAPI(settings.KAVENEGAR_API_KEY)
        params = {
            'receptor': phone,
            'message': f'Your OTP code is {code}'
        }
        send_phone.delay(api, params)
    except Exception as e:
        print(e)
