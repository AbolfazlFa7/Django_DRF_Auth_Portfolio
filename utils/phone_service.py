from kavenegar import KavenegarAPI
from django.conf import settings


def send_verification_code(phone, code):
    try:
        api = KavenegarAPI(settings.KAVENEGAR_API_KEY)
        params = {
            'receptor': phone,
            'message': f'Your OTP code is {code}'
        }
        api.sms_send(params)
    except Exception as e:
        print(e)
