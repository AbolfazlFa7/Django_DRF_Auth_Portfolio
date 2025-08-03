from django.contrib.auth.models import AbstractUser
from django.utils import timezone
from django.db import models
from .manager import UserManager
from django.conf import settings
import secrets


class User(AbstractUser):
    birthday = models.DateField(null=True, blank=True)
    gender = models.CharField(max_length=1, choices=(
        ('M', 'Male'), ('F', 'Female')), default='M')
    phone = models.CharField(
        max_length=11, null=True, blank=True, unique=True)
    email = models.EmailField(unique=True)
    is_verified = models.BooleanField(default=False)
    objects = UserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []

    def __str__(self):
        return self.email

    @property
    def full_name(self):
        return f'{self.first_name} {self.last_name}'

    @property
    def age(self):
        return timezone.now().year - self.birthday.year


class VerificationCode(models.Model):
    code = models.IntegerField(null=True, blank=True)
    user = models.ForeignKey('api.User', on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()

    def __str__(self):
        return self.user

    @classmethod
    def generate_for_user(cls, user):
        existing_code = cls.objects.filter(user=user).first()
        if existing_code and timezone.now() < existing_code.expires_at:
            return None
        if existing_code:
            code = secrets.randbelow(900000) + 100000
            existing_code.code = code
            existing_code.expires_at = timezone.now(
            ) + timezone.timedelta(minutes=settings.OTP_EXPIRY_MINUTES)
            existing_code.save()
            return code

        code = secrets.randbelow(900000) + 100000
        expires_at = timezone.now() + timezone.timedelta(minutes=settings.OTP_EXPIRY_MINUTES)
        new_code = cls(user=user, code=code, expires_at=expires_at)
        new_code.save()
        return code

    def verify(self, code):
        return self.code == code and timezone.now() < self.expires_at
