from django.contrib.auth import get_user_model
from django.contrib.auth.backends import ModelBackend
from django.utils.translation import gettext_lazy as _
from rest_framework.exceptions import NotFound, ValidationError

User = get_user_model()

class EmailAuthBackend(ModelBackend):
    def authenticate(self, request, email, password, **kwargs):
        if not email:
            raise ValidationError(_("Email is required"))
        
        try:
            user = User.objects.get(email=email, is_email_verified=True, is_active=True)
        except User.DoesNotExist:
            raise NotFound(
                {"message": _("Please enter correct email and password for login.")}
            )
        
        if user.check_password(password):
            return user
        
        raise ValidationError(
            {"message": _("Please enter correct email and password for login.")}
        )
     

class PhoneAuthBackend(ModelBackend):
    def authenticate(self, request,country_code, phone, password, **kwargs):
        if not phone:
            raise ValidationError(
                {"message": _("Phone number is required")}
            )
        
        try:
            user = User.objects.get(country_code=country_code, phone=phone, is_phone_verified=True, is_active=True)
        except User.DoesNotExist:
            raise NotFound(
                {"message": _("Please enter correct phone number and password for login.")}
            )
        
        if user.check_password(password):
            return user
        
        raise ValidationError(
            {"message": _("Please enter correct phone number and password for login.")}
        )