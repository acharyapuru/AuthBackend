from django.shortcuts import render
from django.conf import settings
from django.utils import timezone
from datetime import datetime
from django.db import transaction
from django.contrib.auth import get_user_model, authenticate
from django.contrib.auth.models import update_last_login, AnonymousUser
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.exceptions import NotFound, PermissionDenied
from rest_framework.views import APIView
from rest_framework import mixins
from rest_framework.decorators import action
from rest_framework.viewsets import GenericViewSet
from rest_framework.generics import CreateAPIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework import permissions
from django.utils.translation import gettext_lazy as _
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from .models import PseudoUser, UserProfile
from .serializers import (
    EmailOTPRequestSerializer,
    PhoneOTPRequestSerializer,
    EmailOTPVerificationSerializer,
    PhoneOTPVerificationSerializer,
    SignupWithEmailSerializer,
    SignupWithPhoneSerializer,
    LoginWithEmailSerializer,
    LoginWithPhoneSerializer,
    LogoutSerializer,
    PasswordChangeSerializer,
    PasswordResetWithEmailSerializer,
    PasswordResetWithPhoneSerializer,
    UserProfileSerializer,
)

from .utils import (
    generate_otp,
    exceed_otp_resent_attempt,
    validate_otp_request_duration,
    send_otp_to_email,
)
from authbackend.utils import login_checker

User = get_user_model()
# Create your views here.

class EmailOTPRequestAPIView(APIView):
    serializer_class = EmailOTPRequestSerializer
    permission_classes = [permissions.AllowAny]

    @swagger_auto_schema(
            tags=["OTP Request"],
            request_body=EmailOTPRequestSerializer, 
            operation_description="Request OTP to email.",
            operation_id="Email OTP Request"
    )
    @transaction.atomic
    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data.get("email")

        now: datetime = timezone.now()
        otp: str = generate_otp()

        user = User.members.email_user().find_by_email(email)

        if user:
            raise PermissionDenied({"message": _("User with this email already exists.")})
        
        pseudo_user = PseudoUser.objects.find_by_email(email)

        if pseudo_user:
                if pseudo_user.last_otp_resent_at:
                    otp_sent = pseudo_user.otp_sent
                    max_attempt = settings.MAX_OTP_RESENT_ATTEMPT
                    last_otp_resent_at = pseudo_user.last_otp_resent_at
                    otp_block_time = settings.OTP_RESENT_BLOCK_TIME
                    if exceed_otp_resent_attempt(otp_sent, max_attempt) and validate_otp_request_duration(last_otp_resent_at, otp_block_time):
                        opt_resent_block_time_in_hours = (otp_block_time // 60)
                        raise PermissionDenied(
                            {
                                "message": _(f"You are blocked for {opt_resent_block_time_in_hours} hours to resend otp.")
                            }
                        )
                    
                    if validate_otp_request_duration(last_otp_resent_at, settings.OTP_CONT_RESENT_BLOCK_TIME):
                        raise PermissionDenied(
                            {
                                "message": _(f"You are blocked for {settings.OTP_CONT_RESENT_BLOCK_TIME} minues to resend otp.")
                            }
                        )
                    
        else:
            pseudo_user = PseudoUser()
            pseudo_user.email = email
        pseudo_user.otp = otp
        pseudo_user.otp_sent += 1
        pseudo_user.last_otp_resent_at = now
        pseudo_user.save()

        send_otp_to_email(email, pseudo_user.otp)
        return Response(
            {"message": _("OTP has been sent to email.")},
            status=status.HTTP_201_CREATED,
        )          


class PhoneOTPRequestAPIView(APIView):
    serializer_class = PhoneOTPRequestSerializer
    permission_classes = [permissions.AllowAny]

    @swagger_auto_schema(
            tags=["OTP Request"],
            request_body=PhoneOTPRequestSerializer, 
            operation_description="Request OTP to phone.",
            operation_id="Phone OTP Request"
    )
    @transaction.atomic
    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        phone = serializer.validated_data.get("phone")

        now: datetime = timezone.now()
        otp: str = generate_otp()

        user = User.members.phone_user().find_by_phone(phone)

        if user:
            raise PermissionDenied({"message": _("User with this phone number already exists.")})
        
        pseudo_user = PseudoUser.objects.find_by_phone(phone)

        if pseudo_user:
            if pseudo_user.last_otp_resent_at:
                otp_sent = pseudo_user.otp_sent
                max_attempt = settings.MAX_OTP_RESENT_ATTEMPT
                last_otp_resent_at = pseudo_user.last_otp_resent_at
                otp_block_time = settings.OTP_RESENT_BLOCK_TIME
                if exceed_otp_resent_attempt(otp_sent, max_attempt) and validate_otp_request_duration(last_otp_resent_at, otp_block_time):
                    opt_resent_block_time_in_hours = (otp_block_time // 60)
                    raise PermissionDenied(
                        {
                            "message": _(f"You are blocked for {opt_resent_block_time_in_hours} hours to resend otp.")
                        }
                    )
                
                if validate_otp_request_duration(last_otp_resent_at, settings.OTP_CONT_RESENT_BLOCK_TIME):
                    raise PermissionDenied(
                        {
                            "message": _(f"You are blocked for {settings.OTP_CONT_RESENT_BLOCK_TIME} minues to resend otp.")
                        }
                    )
        else:
            pseudo_user = PseudoUser()
            pseudo_user.phone = phone
            
        pseudo_user.otp = otp
        pseudo_user.otp_sent += 1
        pseudo_user.last_otp_resent_at = now
        pseudo_user.save()
        return Response({"message": _("OTP sent to your phone.")}, status=status.HTTP_200_OK)
            
           
class EmailOTPVerificationAPIView(APIView):
    serializer_class = EmailOTPVerificationSerializer
    permission_classes = [permissions.AllowAny]

    @swagger_auto_schema(
            tags=["OTP Verification"],
            request_body=EmailOTPVerificationSerializer, 
            operation_description="Verify OTP sent to email.",
            operation_id="Email OTP Verification"
    )
    @transaction.atomic
    @login_checker
    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data.get("email")

        now = datetime.now()

        pseudo_user = PseudoUser.objects.find_by_email(email)

        if pseudo_user:
            reached_upper_retry_limit = exceed_otp_resent_attempt(pseudo_user.otp_try, settings.MAX_OTP_RETRY)

            if not validate_otp_request_duration(pseudo_user.otp_expiration_time, 0):
                return Response(
                    {
                        "message": _("OTP expired.")
                    },
                    status=status.HTTP_403_FORBIDDEN
                )
            
            if reached_upper_retry_limit:
                if validate_otp_request_duration(pseudo_user.last_otp_retry_at, settings.OTP_RETRY_BLOCK_TIME):
                    return Response(
                        {
                            "message": _("Please try again after some time.")}, 
                            status=status.HTTP_403_FORBIDDEN
                        )
                    
            
            if pseudo_user.otp == serializer.validated_data.get('otp'):
                pseudo_user.is_email_verified = True
                pseudo_user.save()
                return Response(
                    {
                        "message": _("OTP has been verified successfully.")
                    },
                    status=status.HTTP_200_OK
                )
            
            else:
                pseudo_user.otp_try += 1
                pseudo_user.last_otp_retry_at = now
                pseudo_user.save()
                if pseudo_user.otp_try == settings.MAX_OTP_RETRY:
                    return Response(
                        {
                            "message": _(f"You have reached maximum retry limit.Please wait {settings.OTP_RETRY_BLOCK_TIME} minutes to try again.")
                        },
                        status=status.HTTP_403_FORBIDDEN
                    )
                
                return Response(
                    {
                        "message": _("Wrong OTP.")
                    },
                    status=status.HTTP_403_FORBIDDEN
                )
            
        return Response(
            {
                "message": _("User with this email does not exist.")
            },
            status=status.HTTP_404_NOT_FOUND
        )
    

class PhoneOTPVerificationAPIView(APIView):
    serializer_class = PhoneOTPVerificationSerializer
    permission_classes = [permissions.AllowAny]

    @swagger_auto_schema(
            tags=["OTP Verification"],
            request_body=PhoneOTPVerificationSerializer, 
            operation_description="Verify OTP sent to phone.",
            operation_id="Phone OTP Verification"
    )
    @transaction.atomic
    @login_checker
    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        phone = serializer.validated_data.get("phone")

        now = datetime.now()

        pseudo_user = PseudoUser.objects.find_by_phone(phone)

        if pseudo_user:
            reached_upper_retry_limit = exceed_otp_resent_attempt(pseudo_user.otp_try, settings.MAX_OTP_RETRY)

            if not validate_otp_request_duration(pseudo_user.otp_expiration_time, 0):
                return Response(
                    {
                        'message': _("OTP expired.")
                    },
                    status=status.HTTP_403_FORBIDDEN
                )
            
            if reached_upper_retry_limit:
                if validate_otp_request_duration(pseudo_user.last_otp_retry_at, settings.OTP_RETRY_BLOCK_TIME):
                    return Response(
                        {
                            'message': _("Please try again after some time.")
                        },
                        status=status.HTTP_403_FORBIDDEN
                    )
            
            if pseudo_user.otp == serializer.validated_data.get('otp'):
                pseudo_user.is_phone_verified = True
                pseudo_user.save()
                return Response(
                    {
                        'message': _("OTP has been verified successfully.")
                    },
                    status=status.HTTP_200_OK
                )
            
            else:
                pseudo_user.otp_try += 1
                pseudo_user.last_otp_retry_at = now
                pseudo_user.save()
                if pseudo_user.otp_try == settings.MAX_OTP_RETRY:
                    return Response(
                        {
                            'message': _(f"You have reached maximum retry limit.Please wait {settings.OTP_RETRY_BLOCK_TIME} minutes to try again.")
                        },
                        status=status.HTTP_403_FORBIDDEN
                    )
                
                return Response(
                    {
                        'message': _("Wrong OTP.")
                    },
                    status=status.HTTP_403_FORBIDDEN
                )
            
        return Response(
            {
                'message': _("User with this phone does not exist.")
            },
            status=status.HTTP_404_NOT_FOUND
        )


class SignupWithEmailAPIView(CreateAPIView):
    serializer_class = SignupWithEmailSerializer
    permission_classes = [permissions.AllowAny]

    @swagger_auto_schema(tags=["Signup"], operation_description="Signup with email.", operation_id="Signup with email")
    @transaction.atomic
    @login_checker
    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(
            {
                'message': _("User created successfully.")
            },
            status=status.HTTP_201_CREATED
        )


class SignupWithPhoneAPIView(CreateAPIView):
    serializer_class = SignupWithPhoneSerializer
    permission_classes = [permissions.AllowAny]

    @swagger_auto_schema(tags=["Signup"], operation_description="Signup with phone.", operation_id="Signup with phone")
    @transaction.atomic
    @login_checker
    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(
            {
                'message': _("User created successfully.")
            },
            status=status.HTTP_201_CREATED
        )


class LoginWithEmailAPIView(APIView):
    serializer_class = LoginWithEmailSerializer
    permission_classes = [permissions.AllowAny]

    @swagger_auto_schema(tags=["Login"], operation_description="Login user.", request_body=LoginWithEmailSerializer, operation_id="Email Login")
    @transaction.atomic
    @login_checker
    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        authentication_kwargs = {
            "email": serializer.validated_data.get("email"),
            "password": serializer.validated_data.get("password")
        }

        user = authenticate(**authentication_kwargs)

        if not user:
            return Response(
                {
                    'message': _("Invalid credentials.")
                },
                status=status.HTTP_401_UNAUTHORIZED
            )
        refresh_token = RefreshToken.for_user(user)
        acces_token = refresh_token.access_token
        update_last_login(None, user)
        return Response(
            {
                'message': _("User logged in successfully."),
                'access_token': str(acces_token),
                'refresh_token': str(refresh_token)
            },
            status=status.HTTP_200_OK
        )


class LoginWithPhoneAPIView(APIView):
    serializer_class = LoginWithPhoneSerializer
    permission_classes = [permissions.AllowAny]

    @swagger_auto_schema(tags=["Login"], operation_description="Login user.", operation_id="Phone Login", request_body=LoginWithPhoneSerializer)
    @transaction.atomic
    @login_checker
    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        authentication_kwargs = {
            "phone": serializer.validated_data.get("phone"),
            "password": serializer.validated_data.get("password")
        }

        user = authenticate(**authentication_kwargs)

        if user is None:
            return Response(
                {
                    'message': _("Invalid credentials.")
                },
                status=status.HTTP_401_UNAUTHORIZED
            )
        
        refresh_token = RefreshToken.for_user(user)
        acces_token = refresh_token.access_token
        update_last_login(None, user)
        return Response(
            {
                'message': _("User logged in successfully."),
                'access_token': str(acces_token),
                'refresh_token': str(refresh_token)
            },
            status=status.HTTP_200_OK
        )


class LogoutAPIView(APIView):
    serializer_class = LogoutSerializer
    permission_classes = [permissions.IsAuthenticated]

    @swagger_auto_schema(tags=["Logout"], operation_description="Logout user.", request_body=LogoutSerializer, operation_id="Logout")
    @transaction.atomic
    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(
            {
                'message': _("User logged out successfully.")
            },
            status=status.HTTP_200_OK
        )


class ChangePasswordAPIView(CreateAPIView):
    serializer_class = PasswordChangeSerializer
    permission_classes = [permissions.IsAuthenticated]

    @swagger_auto_schema(tags=["Password Change"], operation_description="Change password.", operation_id="Password Change")
    @transaction.atomic
    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data, context={'request': request})
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(
            {
                'message': _("Password changed successfully.")
            },
            status=status.HTTP_200_OK
        )


class PasswordResetOTPWithEmailAPIView(EmailOTPRequestAPIView):
    permission_classes = [permissions.AllowAny]

    @swagger_auto_schema(
            tags=["Password Reset OTP Request"], 
            operation_description="Request OTP to email for password reset.",
            operation_id="Password Reset Email OTP Request",
            request_body=EmailOTPRequestSerializer
    )
    @transaction.atomic
    @login_checker
    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data.get("email")

        now: datetime = timezone.now()
        otp: str = generate_otp()

        user = User.members.find_by_email(email)

        if not user:
            raise NotFound({"message": _("User with this email does not exist.")})
        
        pseudo_user = PseudoUser.objects.find_by_email(email)

        if pseudo_user:
            if pseudo_user.last_otp_resent_at:
                otp_sent = pseudo_user.otp_sent
                max_attempt = settings.MAX_OTP_RESENT_ATTEMPT
                last_otp_resent_at = pseudo_user.last_otp_resent_at
                otp_block_time = settings.OTP_RESENT_BLOCK_TIME

                if (
                    exceed_otp_resent_attempt(otp_sent, max_attempt) and 
                    validate_otp_request_duration(last_otp_resent_at, otp_block_time)):

                    opt_resent_block_time_in_hours = (otp_block_time // 60)
                    raise PermissionDenied(
                        {"message": _(f"You are blocked for {opt_resent_block_time_in_hours} hours to resend otp.")}
                    )
                
                if validate_otp_request_duration(last_otp_resent_at, settings.OTP_CONT_RESENT_BLOCK_TIME):
                    raise PermissionDenied(
                        {"message": _(f"You are blocked for {settings.OTP_CONT_RESENT_BLOCK_TIME} minues to resend otp.")}
                    )
                
        else:
            pseudo_user = PseudoUser()
            pseudo_user.email = email
        pseudo_user.otp = otp
        pseudo_user.otp_sent += 1
        pseudo_user.last_otp_resent_at = now
        pseudo_user.save()

        send_otp_to_email(email, pseudo_user.otp)
        return Response(
            {"message": _("OTP has been sent to email.")},
            status=status.HTTP_201_CREATED,
        )


class PasswordResetOTPWithPhoneAPIView(PhoneOTPRequestAPIView):
    permission_classes = [permissions.AllowAny]

    @swagger_auto_schema(
            tags=["Password Reset OTP Request"], 
            operation_description="Request OTP to phone for password reset.",
            operation_id="Password Reset Phone OTP Request",
            request_body=PhoneOTPRequestSerializer
    )
    @transaction.atomic
    @login_checker
    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        phone = serializer.validated_data.get("phone")

        now: datetime = timezone.now()
        otp: str = generate_otp()

        user = User.members.find_by_phone(phone)

        if not user:
            raise NotFound({"message": _("User with this phone number does not exist.")})
        
        pseudo_user = PseudoUser.objects.find_by_phone(phone)

        if pseudo_user:
            if pseudo_user.last_otp_resent_at:
                otp_sent = pseudo_user.otp_sent
                max_attempt = settings.MAX_OTP_RESENT_ATTEMPT
                last_otp_resent_at = pseudo_user.last_otp_resent_at
                otp_block_time = settings.OTP_RESENT_BLOCK_TIME

                if (
                    exceed_otp_resent_attempt(otp_sent, max_attempt) and 
                    validate_otp_request_duration(last_otp_resent_at, otp_block_time)):

                    opt_resent_block_time_in_hours = (otp_block_time // 60)
                    raise PermissionDenied(
                        {"message": _(f"You are blocked for {opt_resent_block_time_in_hours} hours to resend otp.")}
                    )
                
                if validate_otp_request_duration(last_otp_resent_at, settings.OTP_CONT_RESENT_BLOCK_TIME):
                    raise PermissionDenied(
                        {"message": _(f"You are blocked for {settings.OTP_CONT_RESENT_BLOCK_TIME} minues to resend otp.")}
                    )
                
        else:
            pseudo_user = PseudoUser()
            pseudo_user.phone = phone
        pseudo_user.otp = otp
        pseudo_user.otp_sent += 1
        pseudo_user.last_otp_resent_at = now
        pseudo_user.save()
        return Response({"message": _("OTP sent to your phone.")}, status=status.HTTP_200_OK)
                    

class PasswordResetOTPVerificationWithEmailAPIView(APIView):
    serializer_class = EmailOTPVerificationSerializer
    permission_classes = [permissions.AllowAny]

    @swagger_auto_schema(
            tags=["Password Reset OTP Verification"], 
            operation_description="Verify OTP sent to email for password reset.",
            operation_id="Password Reset Email OTP Verification",
            request_body=EmailOTPVerificationSerializer
    )
    @transaction.atomic
    @login_checker
    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data.get("email")

        now = datetime.now()

        pseudo_user = PseudoUser.objects.find_by_email(email)

        if pseudo_user:
            reached_upper_retry_limit = exceed_otp_resent_attempt(pseudo_user.otp_try, settings.MAX_OTP_RETRY)

            if not validate_otp_request_duration(pseudo_user.otp_expiration_time, 0):
                return Response(
                    {
                        "message": _("OTP expired.")
                    },
                    status=status.HTTP_403_FORBIDDEN
                )
            
            if reached_upper_retry_limit:
                if validate_otp_request_duration(pseudo_user.last_otp_retry_at, settings.OTP_RETRY_BLOCK_TIME):
                    return Response(
                        {
                            "message": _("Please try again after some time.")}, 
                            status=status.HTTP_403_FORBIDDEN
                        )
            
            if pseudo_user.otp == serializer.validated_data.get('otp'):
                return Response(
                    {
                        "message": _("OTP has been verified successfully.")
                    },
                    status=status.HTTP_200_OK
                )
            
            else:
                pseudo_user.otp_try += 1
                pseudo_user.last_otp_retry_at = now
                pseudo_user.save()
                if pseudo_user.otp_try == settings.MAX_OTP_RETRY:
                    return Response(
                        {
                            "message": _(f"You have reached maximum retry limit.Please wait {settings.OTP_RETRY_BLOCK_TIME} minutes to try again.")
                        },
                        status=status.HTTP_403_FORBIDDEN
                    )
                
                return Response(
                    {
                        "message": _("Wrong OTP.")
                    },
                    status=status.HTTP_403_FORBIDDEN
                )
            
        return Response(
            {
                "message": _("User with this email does not exist.")
            },
            status=status.HTTP_404_NOT_FOUND
        )
    

class PasswordResetOTPVerificationWithPhoneAPIView(APIView):
    serializer_class = PhoneOTPVerificationSerializer
    permission_classes = [permissions.AllowAny]

    @swagger_auto_schema(
            tags=["Password Reset OTP Verification"], 
            operation_description="Verify OTP sent to phone for password reset.",
            operation_id="Password Reset Phone OTP Verification",
            request_body=PhoneOTPVerificationSerializer
    )
    @transaction.atomic
    @login_checker
    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        phone = serializer.validated_data.get("phone")

        now = datetime.now()

        pseudo_user = PseudoUser.objects.find_by_phone(phone)

        if pseudo_user:
            reached_upper_retry_limit = exceed_otp_resent_attempt(pseudo_user.otp_try, settings.MAX_OTP_RETRY)

            if not validate_otp_request_duration(pseudo_user.otp_expiration_time, 0):
                return Response(
                    {
                        'message': _("OTP expired.")
                    },
                    status=status.HTTP_403_FORBIDDEN
                )
            
            if reached_upper_retry_limit:
                if validate_otp_request_duration(pseudo_user.last_otp_retry_at, settings.OTP_RETRY_BLOCK_TIME):
                    return Response(
                        {
                            'message': _("Please try again after some time.")
                        },
                        status=status.HTTP_403_FORBIDDEN
                    )
                
            if pseudo_user.otp == serializer.validated_data.get('otp'):
                return Response(
                    {
                        'message': _("OTP has been verified successfully.")
                    },
                    status=status.HTTP_200_OK
                )
            
            else:
                pseudo_user.otp_try += 1
                pseudo_user.last_otp_retry_at = now
                pseudo_user.save()
                if pseudo_user.otp_try == settings.MAX_OTP_RETRY:
                    return Response(
                        {
                            'message': _(f"You have reached maximum retry limit.Please wait {settings.OTP_RETRY_BLOCK_TIME} minutes to try again.")
                        }
                    )
                
                return Response(
                    {
                        'message': _("Wrong OTP.")
                    },
                    status=status.HTTP_403_FORBIDDEN
                )
            
        return Response(
            {
                'message': _("User with this phone does not exist.")
            },
            status=status.HTTP_404_NOT_FOUND
        )
    

class PasswordResetWithEmailAPIView(APIView):
    serializer_class = PasswordResetWithEmailSerializer
    permission_classes = [permissions.AllowAny]

    @swagger_auto_schema(
            tags=["Password Reset"], 
            operation_description="Reset password with email.",
            operation_id="Password Reset with Email",
            request_body=PasswordResetWithEmailSerializer
    )
    @transaction.atomic
    @login_checker
    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data.get("email")
        otp = serializer.validated_data.get("otp")

        try:
            pseudo_user = PseudoUser.objects.get(email=email, otp=otp)
            pseudo_user.delete()
        except PseudoUser.DoesNotExist:
            return Response(
                {
                    'message': _("Invalid Request.")
                },
                status=status.HTTP_400_BAD_REQUEST
            )
        
        serializer.save()
        return Response(
            {
                'message': _("Password reset successfully.")
            },
            status=status.HTTP_200_OK
        )


class PasswordResetWithPhoneAPIView(APIView):
    serializer_class = PasswordResetWithPhoneSerializer
    permission_classes = [permissions.AllowAny]

    @swagger_auto_schema(
            tags=["Password Reset"], 
            operation_description="Reset password with phone.",
            operation_id="Password Reset with Phone",
            request_body=PasswordResetWithPhoneSerializer
    )
    @transaction.atomic
    @login_checker
    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        phone = serializer.validated_data.get("phone")
        otp = serializer.validated_data.get("otp")

        try:
            pseudo_user = PseudoUser.objects.get(phone=phone, otp=otp)
            pseudo_user.delete()
        except PseudoUser.DoesNotExist:
            return Response(
                {
                    'message':_("Invalid Request")
                },
                status=status.HTTP_400_BAD_REQUEST
            )
        serializer.save()
        return Response(
            {
                'message': _("Password reset successfully.")
            },
            status=status.HTTP_200_OK
        )
    

class UserProfileViewSet(GenericViewSet):
    serializer_class = UserProfileSerializer
    permission_classes = [permissions.IsAuthenticated]


    def get_queryset(self):
        if isinstance(self.request.user, AnonymousUser):
            return UserProfile.objects.none()
        return UserProfile.objects.filter(user=self.request.user)
    
    @swagger_auto_schema(tags=["Profile"], operation_description="Get user profile.", operation_id="Own Profile")
    @action(detail=False, methods=['get'], permission_classes=[permissions.IsAuthenticated])
    def me(self, request):
        profile = self.get_queryset().first()
        serializer = self.serializer_class(profile)
        return Response(
            {
                'message': _("Profile fetched successfully."),
                'data': serializer.data
            },
            status=status.HTTP_200_OK
        )
    # to achieve put method only for update use use update method in place of edit
    @swagger_auto_schema(tags=["Profile"], operation_description="Update user profile.", operation_id="Update Profile")
    @action(detail=False, methods=['put'], permission_classes=[permissions.IsAuthenticated])
    def edit(self, request):
        profile = self.get_queryset().first()

        if profile is None:
            raise NotFound({"message": _("Profile not found.")})
        
        serializer = self.serializer_class(profile, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(
            {
                'message': _("Profile updated successfully."),
                'data': serializer.data
            },
            status=status.HTTP_200_OK
        )
