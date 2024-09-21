from rest_framework import serializers
from .utils import phone_validator_function, otp_validator, otp_validator_func, Base64ImageField
from django.utils.translation import gettext_lazy as _
from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from rest_framework.exceptions import NotFound
from rest_framework_simplejwt.tokens import RefreshToken
from .models import PseudoUser, UserProfile

User = get_user_model()

class EmailOTPRequestSerializer(serializers.Serializer):
    email = serializers.EmailField(max_length=255)

class PhoneOTPRequestSerializer(serializers.Serializer):
    country_code = serializers.CharField(max_length=6)
    phone = serializers.CharField(max_length=10)

    def validate(self, attrs):
        country_code = attrs.get("country_code")
        phone = attrs.get("phone")
        phone_validator_function(country_code, phone)
        return super().validate(attrs)
    
class VerifyOTPSerializer(serializers.Serializer):
    otp = serializers.CharField(max_length=5)

    def validate(self, attrs):
        otp = attrs.get("otp")
        if not otp_validator_func(otp):
            raise serializers.ValidationError({"message": _("Enter a valid 5-digit OTP")})
        return super().validate(attrs)
    
    class Meta:
        abstract = True

class EmailOTPVerificationSerializer(VerifyOTPSerializer):
    email = serializers.EmailField(max_length=255)

    def validate(self, attrs):
        return super().validate(attrs)

    class Meta:
        fields = ["email", "otp"]

class PhoneOTPVerificationSerializer(VerifyOTPSerializer):
    country_code = serializers.CharField(max_length=6)
    phone = serializers.CharField(max_length=10)

    def validate(self, attrs):
        country_code = attrs.get("country_code")
        phone = attrs.get("phone")
        phone_validator_function(country_code, phone)
        return super().validate(attrs)
    
    class Meta:
        fields = ["country_code", "phone", "otp"]



class UserRegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(
        write_only=True, 
        required=True,
        trim_whitespace=True
    )

    confirm_password = serializers.CharField(
        write_only=True, 
        required=True,
        trim_whitespace=True
    )

    def validate(self, attrs):

        if attrs.get("password") != attrs.get("confirm_password"):
            raise serializers.ValidationError(
                {"message": _("Passwords do not match")}
            )
        
        if attrs.get('password') == '' or attrs.get('confirm_password') == '':
            raise serializers.ValidationError(
                {"message": _("Password cannot be empty")}
            )
        
        validate_password(attrs.get('password'))
        return attrs
    
    def create(self, validated_data):
        password = validated_data.pop("password")
        _ = validated_data.pop("confirm_password")
        instance = super().create(validated_data)
        instance.set_password(password)
        instance.save()
        return instance


class SignupWithEmailSerializer(UserRegisterSerializer):
    class Meta:
        model = User
        fields = ['email', 'password', 'confirm_password']

        extra_kwargs = {
            'email': {'required': True},
        }


    def validate(self, attrs):
        email = attrs.get("email")

        pseudo_user = PseudoUser.objects.email_verified().find_by_email(email)
        if not pseudo_user:
            raise NotFound(
                {"message": _("The credentials have not been verified")}
            )
        return super().validate(attrs)


class SignupWithPhoneSerializer(UserRegisterSerializer):
    class Meta:
        model = User
        fields = ['country_code', 'phone', 'password', 'confirm_password']

        extra_kwargs = {
            'country_code': {'required': True},
            'phone': {'required': True},
        }

    def validate(self, attrs):
        country_code = attrs.get("country_code")
        phone = attrs.get("phone")
        phone_validator_function(country_code, phone)

        pseudo_user = PseudoUser.objects.phone_verified().find_by_phone(phone)
        if not pseudo_user:
            raise NotFound(
                {"message": _("The credentials have not been verified")}
            )
        return super().validate(attrs)
    

class LogoutSerializer(serializers.Serializer):
    refresh_token = serializers.CharField()
    default_error_messages = {"bad_token": _("Token is invalid or expired")}

    def validate(self, attrs):
        self.token = attrs["refresh_token"]
        return attrs
    
    def save(self, **kwargs):
        try:
            RefreshToken(self.token).blacklist()
        except Exception:
            self.fail("bad_token")


class LoginSerializer(serializers.Serializer):
    password = serializers.CharField(
        write_only=True, 
        required=True,
        trim_whitespace=True
    )

    class Meta:
        abstract = True


class LoginWithEmailSerializer(LoginSerializer):
    email = serializers.EmailField(max_length=255)

    class Meta:
        fields = ["email", "password"]


class LoginWithPhoneSerializer(LoginSerializer):
    country_code = serializers.CharField(max_length=6)
    phone = serializers.CharField(max_length=10)

    class Meta:
        fields = ["country_code", "phone", "password"]
    
    def validate(self, attrs):
        country_code = attrs.get("country_code")
        phone = attrs.get("phone")
        phone_validator_function(country_code, phone)
        return super().validate(attrs)
    

class PasswordChangeSerializer(serializers.Serializer):
    # trim_whitespace is true by default in serializer fields
    old_password = serializers.CharField(
        write_only=True, 
    )

    new_password = serializers.CharField(
        write_only=True, 
    )

    confirm_new_password = serializers.CharField(
        write_only=True, 
    )

    def validate(self, attrs):

        if attrs.get("new_password") != attrs.get("confirm_new_password"):
            raise serializers.ValidationError(
                {"message": _("Passwords do not match")}
            )
        
        if attrs.get("new_password") == '' or attrs.get("confirm_new_password") == '':
            raise serializers.ValidationError(
                {"message": _("Password cannot be empty")}
            )
        
        if not self.context["request"].user.check_password(attrs.get("old_password")):
            raise serializers.ValidationError(
                {"message": _("Old password is incorrect")}
            )
        
        validate_password(attrs.get("new_password"))
        return attrs
    
    def save(self, **kwargs):
        new_password = self.validated_data.get("new_password")
        self.context["request"].user.set_password(new_password)
        self.context["request"].user.save()
        return self.context["request"].user
    
class PasswordResetSerializer(serializers.Serializer):
    # required false means the field is not required in the request( by default all fields are required)
    # allow_blank true means the field can be empty(especially use with textual fields)
    # allow_null true means the field can be null(especially use with non-textual fields i.e. numbers)
    # all serializer fields are required true by default

    otp = serializers.CharField(
        max_length=5,
        required=False,
        allow_null=True,
    )

    password = serializers.CharField(
        write_only=True,
        validators=[validate_password],
    )

    confirm_password = serializers.CharField(
        write_only=True,
    )

    class Meta:
        abstract = True

    def validate(self, attrs):
        otp = attrs.get("otp")

        if not otp:
            raise serializers.ValidationError(
                {"message": _("OTP is required")}
            )
        
        if not otp_validator_func(otp):
            raise serializers.ValidationError(
                {"message": _("Enter a valid 5-digit OTP")}
            )
        
        if attrs.get("password") != attrs.get("confirm_password"):
            raise serializers.ValidationError(
                {"message": _("Passwords do not match")}
            )
        
        validate_password(attrs.get("password"))
        return attrs


class PasswordResetWithEmailSerializer(PasswordResetSerializer):
    email = serializers.EmailField(
        max_length=255, 
    )

    class Meta:
        fields = ["email", "otp", "password", "confirm_password"]

    def validate(self, attrs):
        return super().validate(attrs)
    
    def save(self, *args, **kwargs):
        email = self.validated_data.get("email")
        password = self.validated_data.get("password")

        user = User.members.email_user().find_by_email(email)
        if user:
            user.set_password(password)
            user.save()
            return user
        else:
            raise NotFound(
                {"message": _("User not found")}
            )

class PasswordResetWithPhoneSerializer(PasswordResetSerializer):
    country_code = serializers.CharField(max_length=6)
    phone = serializers.CharField(max_length=10)

    class Meta:
        fields = ["country_code", "phone", "otp", "password", "confirm_password"]

    def validate(self, attrs):
        country_code = attrs.get("country_code")
        phone = attrs.get("phone")
        phone_validator_function(country_code, phone)
        return super().validate(attrs)
    
    def save(self, *args, **kwargs):
        country_code = self.validated_data.get("country_code")
        phone = self.validated_data.get("phone")
        password = self.validated_data.get("password")

        user = User.members.phone_user().find_by_phone(phone)
        if user:
            user.set_password(password)
            user.save()
            return user
        else:
            raise NotFound(
                {"message": _("User not found")}
            )
        

class UserProfileSerializer(serializers.ModelSerializer):
    username = serializers.SerializerMethodField()
    profile_picture = Base64ImageField(required=False)
    class Meta:
        model = UserProfile
        fields = ["username","first_name", "last_name", "profile_picture", "date_of_birth", "address"]

        extra_kwargs = {
            'username': {'read_only': True},
        }
    
    def get_username(self, obj):
        return str(obj.user)