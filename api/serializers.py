from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from rest_framework import serializers
from django.contrib.auth import get_user_model
from utils.validators import validate_password, normalize_email, validate_phone
from rest_framework.response import Response

User = get_user_model()


class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    def validate(self, attrs):
        data = super().validate(attrs)
        data['email'] = self.user.email
        return data


class UsersSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('url', 'email', 'password', 'id', 'first_name', 'last_name',)
        extra_kwargs = {
            'url': {'view_name': 'api:user', 'lookup_field': 'pk'},
            'first_name': {'style': {'placeholder': 'Not Required'}, 'help_text': 'First Name'},
            'last_name': {'style': {'placeholder': 'Not Required'}, 'help_text': 'Last Name'},
            'password': {'min_length': 8, 'max_length': 20, 'help_text': 'Password', 'write_only': True, 'style': {'input_type': 'password', 'placeholder': 'Password'}},
            'email': {'style': {'placeholder': 'Email'}, 'help_text': 'Email'},
        }

    def create(self, validated_data):
        user = User.objects.create_user(**validated_data, validator=False)
        return user

    def validate_password(self, value):
        return validate_password(value, )

    def validate_email(self, email):
        return normalize_email(email)


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'email', 'phone', 'first_name',
                  'last_name', 'is_verified', 'birthday', 'gender']
        extra_kwargs = {
            'email': {'style': {'placeholder': 'Email'}, 'help_text': 'Email'},
            'phone': {'style': {'placeholder': 'Phone'}, 'help_text': 'Phone'},
            'is_verified': {'read_only': True},
            'first_name': {'style': {'placeholder': 'First Name'}, 'help_text': 'First Name'},
            'last_name': {'style': {'placeholder': 'Last Name'}, 'help_text': 'Last Name'},
        }

    def validate_password(self, value):
        return validate_password(value)

    def validate_email(self, email):
        return normalize_email(email)

    def validate_phone(self, phone):
        return validate_phone(phone)


class LogoutSerializers(serializers.Serializer):
    refresh = serializers.CharField(
        style={'input_type': 'hidden'}, help_text='refresh token')


class SendOTPSerializers(serializers.Serializer):
    email_or_phone = serializers.ChoiceField(
        ['email', 'phone'], help_text="'phone' or 'email'")


class VerifyOTPSerializers(serializers.Serializer):
    code = serializers.IntegerField(required=True, help_text='Code')

    def validate_code(self, code):
        if len(str(code)) != 6:
            return Response({'status': 'Invalid Code'}, status=400)
        else:
            return code
