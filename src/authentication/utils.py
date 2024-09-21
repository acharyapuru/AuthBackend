import io
import re
import uuid
import six
import secrets
import string
import base64
from PIL import Image
from django.core.files.base import ContentFile
from django.conf import settings
from datetime import datetime, timedelta
from django.utils import timezone
from django.core.validators import RegexValidator
from django.utils.translation import gettext_lazy as _
from rest_framework.exceptions import ValidationError
from authbackend.email_thread import EmailThread
from rest_framework import serializers


nepal_phone_validator = RegexValidator(
    regex=r'^(98|97|96)\d{8}$',
    message=_("Enter a valid 10-digit Nepalese phone number starting with 98, 97, or 96")
)

otp_validator = RegexValidator(
    regex=r'^\d{5}$',
    message=_("Enter a valid 5-digit OTP")
)

def phone_validator_function(country_code, phone):
    if country_code in ["+977", "977", ] and phone[0] != "9":
        raise ValidationError(
            {"message": _("Enter a valid 10-digit Nepalese phone number starting with 98, 97, or 96")}
        )
    

def generate_otp(length=5):
    return "".join(secrets.choice(string.digits) for _ in range(length))


def exceed_otp_resent_attempt(current_attempt: int , max_attempt: int):
    """
    Check if the current OTP request attempt have exceeded the maximum allowed.
    """
    return current_attempt >= max_attempt

def validate_otp_request_duration(otp_sent_time : datetime, otp_block_time: int) -> bool:
    """
    Validate if the OTP request is within the allowed time frame.
    """
    now = timezone.now()
    sent_otp_time_in_current_tz: datetime = timezone.localtime(otp_sent_time)
    return now - sent_otp_time_in_current_tz < timedelta(minutes=otp_block_time)


def send_otp_to_email(email_address: str, otp: str) -> None:
    # send otp to email
    subject = "Your OTP"
    message = f"Your OTP is {otp}"
    email_from = settings.EMAIL_HOST_USER
    recepient_list = [email_address, ]
    msg = EmailThread(subject, message, email_from, recepient_list).start()


def otp_validator_func(value):
    otp_regex = re.compile(r'^\d{5}$')
    if otp_regex.match(value):
        return True
    return False


class Base64ImageField(serializers.ImageField):
    """
    Custom serializer field for handling base64 encoded image data.
    """
    class Meta:
        swagger_schema_fields = {
            "type": "string",
            "format": "base64",
            "title": "Base64 Image",
            "description": "Base64 image data",
            "read_only": False,
        }

    def to_internal_value(self, data):
        if isinstance(data, six.string_types):
            if 'data:' in data and ';base64,' in data:
                header, data = data.split(';base64,', 1)
                
                try:
                    # Decode the base64 string
                    decoded_file = base64.b64decode(data)
                except Exception as e:
                    raise serializers.ValidationError("Invalid base64 image data.") from e

                # Determine the file extension
                file_extension = self.get_file_extension(decoded_file)

                # Generate a unique file name
                file_name = f"{uuid.uuid4().hex[:12]}.{file_extension}"

                # Create a ContentFile
                data = ContentFile(decoded_file, name=file_name)

        return super().to_internal_value(data)

    def get_file_extension(self, decoded_file):
        try:
            # Use PIL to determine the file type
            image = Image.open(io.BytesIO(decoded_file))
            image_type = image.format.lower()  # Get the format of the image (e.g., 'jpeg', 'png')
            # Convert 'jpeg' to 'jpg'
            if image_type == 'jpeg':
                return 'jpg'
            return image_type
        except Exception as e:
            raise serializers.ValidationError("Unsupported image format.") from e