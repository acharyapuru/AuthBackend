from django.urls import path, include
from rest_framework import routers
from rest_framework_simplejwt.views import TokenRefreshView
from . import views

router = routers.DefaultRouter()
router.register('profile', views.UserProfileViewSet, basename='profile')


urlpatterns = [
    path('', include(router.urls)),
    path('email-otp-request/', views.EmailOTPRequestAPIView.as_view(), name='email-otp-request'),
    path('phone-otp-request/', views.PhoneOTPRequestAPIView.as_view(), name='phone-otp-request'),
    path('email-otp-verify/', views.EmailOTPVerificationAPIView.as_view(), name='email-otp-verify'),
    path('phone-otp-verify/', views.PhoneOTPVerificationAPIView.as_view(), name='phone-otp-verify'),
    path('email-signup/', views.SignupWithEmailAPIView.as_view(), name='signup-email'),
    path('phone-signup/', views.SignupWithPhoneAPIView.as_view(), name='signup-phone'),
    path('email-login/', views.LoginWithEmailAPIView.as_view(), name='email-login'),
    path('phone-login/', views.LoginWithPhoneAPIView.as_view(), name='phone-login'),
    path('logout/', views.LogoutAPIView.as_view(), name='logout'),
    path('change-password/', views.ChangePasswordAPIView.as_view(), name='change-password'),
    path('password-reset-email-otp/', views.PasswordResetOTPWithEmailAPIView.as_view(), name='password-reset-otp-email'),
    path('password-reset-phone-otp/', views.PasswordResetOTPWithPhoneAPIView.as_view(), name='password-reset-otp-phone'),
    path('password-reset-email-otp-verify', views.PasswordResetOTPVerificationWithEmailAPIView.as_view(), name='password-reset-otp-verify-email'),
    path('password-reset-phone-otp-verify', views.PasswordResetOTPVerificationWithPhoneAPIView.as_view(), name='password-reset-otp-verify-phone'),
    path('password-reset-email', views.PasswordResetWithEmailAPIView.as_view(), name='password-reset-email'),
    path('password-reset-phone', views.PasswordResetWithPhoneAPIView.as_view(), name='password-reset-phone'),
    path('token-refresh/', TokenRefreshView.as_view(), name='token-refresh'),
]
