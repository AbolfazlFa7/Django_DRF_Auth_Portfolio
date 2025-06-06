from django.core.cache import cache
from django.contrib.auth import get_user_model
from . import phone_service
from . import email_service
from api.models import VerificationCode
from rest_framework import status

User = get_user_model()


class OTPService:
    @staticmethod
    def send_otp(user, email_or_phone):
        """
        send OTP code to user phone or email
        Input:
            user: User object
            email_or_phone: 'email' or 'phone'
        Output:
            dict: {'status': 'Message'}, status.HTTP_200_OK}
        """

        if email_or_phone == 'email':
            value = user.email
        else:
            value = user.phone
            if not value:
                return {'status': 'User Phone Number has not submited'}, status.HTTP_400_BAD_REQUEST

        # see if user is verified
        if user.is_verified:
            return {'status': 'User already is verified'}, status.HTTP_400_BAD_REQUEST

        # User exist or not
        user_exists = User.objects.filter(**{email_or_phone: value}).first()
        if not user_exists:
            return {'status': 'User Not Exists'}, status.HTTP_400_BAD_REQUEST

        # create code, if code not expired yet, it return None
        code = VerificationCode.generate_for_user(user)
        if not code:
            return {'status': 'Code already has been sented'}, status.HTTP_400_BAD_REQUEST

        # sending code to user
        if email_or_phone == 'email':
            email_service.send_verification_code(value, code)
        else:
            phone_service.send_verification_code(value, code)

        return {'status': 'code has been sent to user'}, status.HTTP_200_OK

    @staticmethod
    def verify_otp(user, code):
        """
        Verify the OTP code sent to the user.
        Input:
            user: User object
            code: OTP code provided by the user
        Output:
            dict: {'status': 'Message'}, status.HTTP_200_OK or status.HTTP_400_BAD_REQUEST
        """

        # Check if user is already verified in cache
        if cache.get(user.email):
            return {'status': 'User has Verified already'}, status.HTTP_400_BAD_REQUEST

        # Get the verification code for the user
        verification_code = VerificationCode.objects.filter(user=user).first()
        if not verification_code:
            return {'status': 'Invalid Code'}, status.HTTP_400_BAD_REQUEST

        # Verify the code
        if verification_code.verify(code):
            if user.is_verified:
                cache.set(user.email, 'User has Verified already', 60*60)
                return {'status': 'User has Verified already'}, status.HTTP_400_BAD_REQUEST
            user.is_verified = True
            user.save()
            return {'status': 'User has Verified'}, status.HTTP_200_OK
        return {'status': 'Invalid Code'}, status.HTTP_400_BAD_REQUEST
