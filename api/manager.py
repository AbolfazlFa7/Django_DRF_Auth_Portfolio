from django.contrib.auth.models import UserManager
from utils.validators import normalize_email, validate_password
from django.core.exceptions import ValidationError


class UserManager(UserManager):
    def create_user(self, email, password, validator=True, **extra_fields):
        """
        Creates a user with the provided email and password.
        If validator=True, email and password are validated using normalize_email and validate_password.
        If validator=False, validation is assumed to be handled elsewhere (e.g., in a serializer).(if in validate of an serializer, an ValidationError exception will be raised, it show the error in the response, but out of validate of serializer, it will not show error in response !!!!)
        Note: When validator=True, ValidationError exceptions are raised server-side and may not be user-friendly in API responses.
        """

        if not all([email, password]):
            raise ValidationError('Enter email and password Correctly')
        if validator:
            email = normalize_email(email)
            password = validate_password(password)
        user = self.model(email=email, username=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password, **extra_fields):
        user = self.create_user(email, password, **extra_fields)
        user.is_superuser = True
        user.is_staff = True
        user.is_verified = True
        user.save(using=self._db)
        return user
