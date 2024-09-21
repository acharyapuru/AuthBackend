from typing import Iterable
import uuid
from django.utils import timezone
from django.conf import settings
from datetime import timedelta
from django.db import models
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin
from .manager import CustomUserManager
from .utils import nepal_phone_validator, otp_validator
from authbackend.mixins import TimestampMixin
from django.utils.translation import gettext_lazy as _
from .manager import UserFilterManager, PseudoUserManager

# Create your models here.
class User(AbstractBaseUser, PermissionsMixin , TimestampMixin):
    uuid = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
        editable=False,
        unique=True
    )

    username = None
    first_name = None
    last_name = None

    country_code = models.CharField(
        max_length=5,
        default="+977",
        null=True,
        blank=True
    )

    phone = models.CharField(
        max_length=15,
        unique=True,
        null=True,
        blank=True,
        validators=[nepal_phone_validator]
    )

    email = models.EmailField(
        max_length=255,
        unique=True,
        null=True,
        blank=True
    )

    is_email_verified = models.BooleanField(
        default=False
    )

    is_phone_verified = models.BooleanField(
        default=False
    )

    is_active = models.BooleanField(
        default=False
    )

    is_staff = models.BooleanField(
        default=False
    )

    objects = CustomUserManager()

    members = UserFilterManager() # used for filtering

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []

    def clean(self) -> None:
        super().clean()
        if not self.email and not self.phone:
            raise ValueError(
                {
                    'non_field_error': _('Either email or phone is required')
                }
            )
    
    def save(self, *args, **kwargs) -> None:
        self.clean()
        if not(self.is_email_verified or self.is_phone_verified):
            self.is_active = False
        return super().save(*args, **kwargs)
    
    def __str__(self) -> str:
        return self.email or self.phone
    
    class Meta:
        verbose_name = _('User')
        verbose_name_plural = _('Users')
        indexes = [
            models.Index(fields=['phone']),
            models.Index(fields=['email'])
        ]
        constraints = [
           models.CheckConstraint(
               check=~models.Q(is_email_verified=True, email__isnull=True),
               name='email_verified_requires_email',
               violation_error_message=_('Email verification requires email')
            ),
            models.CheckConstraint(
                check=~models.Q(is_phone_verified=True, phone__isnull=True),
                name='phone_verified_requires_phone',
                violation_error_message=_('Phone verification requires phone')
            ),
        ]



class PseudoUser(TimestampMixin):
    uuid = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
        editable=False,
        unique=True
    )

    email = models.EmailField(
        max_length=255,
        unique=True,
        null=True,
    )

    country_code = models.CharField(
        max_length=5,
        null=True,
        blank=True
    )

    phone = models.CharField(
        max_length=15,
        unique=True,
        null=True,
        validators=[nepal_phone_validator]
    )

    otp = models.CharField(
        max_length=6,
        validators=[otp_validator]
    )

    otp_created_at = models.DateTimeField(auto_now_add=True)

    last_otp_resent_at = models.DateTimeField(null=True)

    last_otp_retry_at = models.DateTimeField(null=True)

    otp_try = models.PositiveSmallIntegerField(default=0)

    otp_sent = models.PositiveIntegerField(default=0)

    is_email_verified = models.BooleanField(
        default=False
    )

    is_phone_verified = models.BooleanField(
        default=False
    )

    otp_expiration_time = models.DateTimeField(null=True)

    objects = PseudoUserManager()

    def __str__(self) -> str:
        return self.email or self.phone
    
    class Meta:
        verbose_name = _('Pseudo User')
        verbose_name_plural = _('Pseudo Users')
        indexes = [
            models.Index(fields=['phone']),
            models.Index(fields=['email'])
        ]
        
    def clean(self) -> None:
        super().clean()
        if not self.email and not self.phone:
            raise ValueError(
                {
                    'non_field_error': _('Either email or phone is required')
                }
            )
            
    def save(self, *args, **kwargs):
        self.clean()
        if self.last_otp_resent_at:
            self.otp_expiration_time = self.last_otp_resent_at + timedelta(minutes=settings.OTP_LIFETIME)
        
        else:
            now = timezone.now()
            self.last_otp_resent_at = now
            self.otp_expiration_time = now + timedelta(minutes=settings.OTP_LIFETIME)
        return super().save(*args, **kwargs)
    

class UserProfile(TimestampMixin):
    user = models.OneToOneField(
        User,
        on_delete=models.CASCADE,
        related_name='profile'
    )

    first_name = models.CharField(
        max_length=255,
        null=True,
        blank=True
    )

    last_name = models.CharField(
        max_length=255,
        null=True,
        blank=True
    )

    address = models.CharField(
        max_length=255,
        null=True,
        blank=True
    )

    date_of_birth = models.DateField(
        null=True,
        blank=True
    )

    profile_picture = models.ImageField(
        upload_to='profile_pictures',
        null=True,
        blank=True
    )

    def __str__(self) -> str:
        return self.user.email or self.user.phone
    
    class Meta:
        verbose_name = _('User Profile')
        verbose_name_plural = _('User Profiles')
        indexes = [
            models.Index(fields=['user'])
        ]