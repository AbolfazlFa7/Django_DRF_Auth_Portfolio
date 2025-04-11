from django.contrib.auth.models import UserManager
from utils.validators import normalize_email, validate_password
from django.core.exceptions import ValidationError


class UserManager(UserManager):
    def create_user(self, email, password, validator=True, **extra_fields):
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
