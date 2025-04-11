from utils import email_service
from utils import phone_service
from django.contrib.auth import get_user_model
from rest_framework import generics
from rest_framework import permissions
from rest_framework import status
from rest_framework.response import Response
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework_simplejwt.tokens import RefreshToken
from drf_spectacular.utils import extend_schema, OpenApiExample, OpenApiResponse
from .permissions import IsOwnerOrAdmin, IsAnonymous
from .models import VerificationCode
from . import serializers
from rest_framework.throttling import UserRateThrottle
from django.core.cache import cache


class OTPSendThrottle(UserRateThrottle):
    def parse_rate(self, rate):
        rate = (1, 120)
        return rate


User = get_user_model()


class TokenObtainPairView(TokenObtainPairView):
    serializer_class = serializers.CustomTokenObtainPairSerializer
    permission_classes = [permissions.AllowAny]


class UsersApiView(generics.ListCreateAPIView):
    queryset = User.objects.all()
    serializer_class = serializers.UsersSerializer
    lookup_field = 'pk'

    def get_permissions(self):
        if self.request.method == 'POST':
            return [IsAnonymous()]
        elif self.request.method == 'GET' or self.request.method == 'OPTIONS':
            return [permissions.IsAdminUser()]
        else:
            return [permissions.AllowAny()]


class UserApiView(generics.RetrieveUpdateDestroyAPIView):
    queryset = User.objects.all()
    serializer_class = serializers.UserSerializer
    permission_classes = [IsOwnerOrAdmin]


class LogoutApiView(generics.GenericAPIView):
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = serializers.LogoutSerializers

    @extend_schema(
        description='It get refresh token of user and blacklist it',
        summary='Logout user',
        responses={
            200: OpenApiResponse(
                response=dict,
                description="Successfully logged out",
                examples=[
                    OpenApiExample(
                        name="Success Response",
                        value={
                            "status": "You have logged out"
                        },
                        status_codes=[200]
                    )
                ]
            ),
            403: OpenApiResponse(
                response=dict,
                description="User must be logged in",
                examples=[
                    OpenApiExample(
                        name="Success Response",
                        value={
                            "status": "You are not logged in"
                        },
                        status_codes=[403]
                    )
                ]
            )
        }
    )
    def post(self, request):
        refresh_token = request.data.get('refresh')
        refresh_token = RefreshToken(refresh_token)
        refresh_token.blacklist()
        return Response({'status': 'You have logged out'}, status=status.HTTP_200_OK)


class SendOTPApiView(generics.GenericAPIView):
    serializer_class = serializers.SendOTPSerializers
    permission_classes = [permissions.IsAuthenticated]
    throttle_classes = [OTPSendThrottle]

    @extend_schema(
        description="Send OTP to user, it ask for send otp to user email or phone (phone number of user must be submited before)",
        summary="Send OTP",
        responses={
            200: OpenApiResponse(
                response=dict,
                description="Successfully sent OTP",
                examples=[
                    OpenApiExample(
                        name="Success Response",
                        value={
                            "status": "OTP has been sent to user"
                        },
                        status_codes=[200]
                    )
                ]
            ),
            400: OpenApiResponse(
                response=dict,
                description="OTP has not been sent to user",
                examples=[
                    OpenApiExample(
                        name="phone number not exists",
                        value={
                            'status': 'User Phone Number has not submited'
                        },
                    ),
                    OpenApiExample(
                        name="otp has not expired yet",
                        value={
                            'status': 'Code already has been sented',
                        }
                    ),
                    OpenApiExample(
                        name="User already is verified",
                        value={
                            'status': 'User already is verified',
                        }
                    ),
                    OpenApiExample(
                        name="User Not Exists",
                        value={
                            'status': 'User Not Exists',
                        }
                    )
                ]
            )
        },
        examples=[
            OpenApiExample(
                name="OTP Sent",
                value={
                    "emaile_or_phone": "email",
                },
                request_only=True
            )
        ]
    )
    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        email_or_phone = request.data.get('email_or_phone')

        if email_or_phone == 'email':
            value = request.user.email
        else:
            value = request.user.phone
            if value == None:
                return Response({'status': 'User Phone Number has not submited'}, status=status.HTTP_400_BAD_REQUEST)

        code = VerificationCode.generate_for_user(request.user)
        if not code:
            return Response({'status': 'Code already has been sented'}, status=status.HTTP_400_BAD_REQUEST)

        if email_or_phone == 'email':
            user = User.objects.filter(email=value).first()
            if user:
                if not user.is_verified:
                    email_service.send_verification_code(value, code)
                else:
                    return Response({'status': 'User already is verified'}, status=status.HTTP_400_BAD_REQUEST)
            else:
                return Response({'status': 'User Not Exists'}, status=status.HTTP_400_BAD_REQUEST)

        elif email_or_phone == 'phone':
            user = User.objects.filter(phone=value).first()
            if user:
                if not user.is_verified:
                    phone_service.send_verification_code(value, code)
                else:
                    return Response({'status': 'User already is verified'}, status=status.HTTP_400_BAD_REQUEST)
            else:
                return Response({'status': 'User Not Exists'}, status=status.HTTP_400_BAD_REQUEST)

        return Response({'status': 'code has been sent to user'}, status=status.HTTP_200_OK)


class VerifyOTPApiView(generics.GenericAPIView):
    serializer_class = serializers.VerifyOTPSerializers
    permission_classes = [permissions.IsAuthenticated]

    @extend_schema(
        description="Verify the OTP code sent to the user. The code must be valid and the user must not be verified already.",
        summary="Verify OTP",
        responses={
            200: OpenApiResponse(
                response=dict,
                description="User successfully verified",
                examples=[
                    OpenApiExample(
                        name="Success Response",
                        value={
                            "status": "User has Verified"
                        },
                        status_codes=[200]
                    )
                ]
            ),
            400: OpenApiResponse(
                response=dict,
                description="Error in OTP verification",
                examples=[
                    OpenApiExample(
                        name="User Already Verified",
                        value={
                            "status": "User has Verified already"
                        }
                    ),
                    OpenApiExample(
                        name="Invalid Code",
                        value={
                            "status": "Invalid Code"
                        }
                    )
                ]
            )
        },
        examples=[
            OpenApiExample(
                name="OTP Verify Request",
                value={
                    "code": "123456"
                },
                request_only=True
            )
        ]
    )
    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        if cache.get(request.user.email):
            return Response({'status': 'User has Verified already'}, status=status.HTTP_400_BAD_REQUEST)

        code = request.data.get('code')
        verification_code = VerificationCode.objects.filter(
            user=request.user).first()

        if verification_code:
            verify_code = verification_code.verify(code)
            if verify_code:
                if request.user.is_verified:
                    cache.set(request.user.email,
                              'User has Verified already', 60*60)
                    return Response({'status': 'User has Verified already'}, status=status.HTTP_400_BAD_REQUEST)
                else:
                    request.user.is_verified = True
                    request.user.save()
                    return Response({'status': 'User has Verified'}, status=status.HTTP_200_OK)
        return Response({'status': 'Invalid Code'})
