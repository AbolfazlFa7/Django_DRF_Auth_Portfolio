from rest_framework_simplejwt.views import TokenRefreshView
from rest_framework_simplejwt.views import TokenVerifyView
from drf_spectacular.views import SpectacularAPIView
from drf_spectacular.views import SpectacularRedocView
from drf_spectacular.views import SpectacularSwaggerView
from django.urls import path
from . import views

app_name = 'api'


urlpatterns = [
    # JWT
    path('token/', views.TokenObtainPairView.as_view(), name='Token'),
    path('token/refresh/', TokenRefreshView.as_view(), name='Token_refresh'),
    path('token/verify/', TokenVerifyView.as_view(), name='Token_verify'),

    # Swagger
    path('schema/', SpectacularAPIView.as_view(), name='schema'),
    path('schema/redoc/',
         SpectacularRedocView.as_view(url_name='api:schema'), name='redoc'),
    path('schema/ui/', SpectacularSwaggerView.as_view(url_name='api:schema'),
         name='schema_ui'),

    # User Management
    path('users/', views.UsersApiView.as_view(), name='users'),
    path('users/<int:pk>/', views.UserApiView.as_view(), name='user'),
    path('logout/', views.LogoutApiView.as_view(), name='logout'),

    # TOTP
    path('otp/send/', views.SendOTPApiView.as_view(), name='send_totp'),
    path('otp/verify/', views.VerifyOTPApiView.as_view(), name='verify_totp'),
]
