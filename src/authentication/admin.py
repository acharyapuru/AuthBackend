from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import PseudoUser, User, UserProfile
from .forms import CustomUserChangeForm, CustomUserCreationForm

# Register your models here.
@admin.register(User)
class AuthUserAdmin(UserAdmin):
    model = User
    form = CustomUserChangeForm
    add_form = CustomUserCreationForm
    list_display = (
        "__str__",
        "is_email_verified",
        "is_phone_verified",
        "is_active",
        "is_staff",
        "is_superuser",
    )

    list_filter = (
        "is_email_verified",
        "is_phone_verified",
        "is_active",
        "is_staff",
        "is_superuser",
        "country_code",
    )

    fieldsets = (
        (None, {"fields": (
            "email", "country_code", "phone", "password", "is_email_verified", "is_phone_verified")}
        ),
        ("Permissions", {"fields": (
            "is_active", "is_staff", "is_superuser", "groups", "user_permissions"
            )}
        ),
    )

    add_fieldsets = (
        (None, {
            "classes": ("wide",),
            "fields": (
                "email", "country_code", "phone", "password1", "password2", 
                "is_staff", "is_active", "is_superuser","groups", "user_permissions"
            ),
        }),
    )

    filter_horizontal = ("groups", "user_permissions")
    search_fields = ("email", "phone")
    ordering = ("created_at", "updated_at", "email")
    # raw_id_fields = ("groups", "user_permissions")
    # date_hierarchy = "created_at"

@admin.register(PseudoUser)
class PseudoUserAdmin(admin.ModelAdmin):
    model = PseudoUser
    list_display = ("email", "country_code", "phone", "is_email_verified", "is_phone_verified",)
    list_filter = (
        "is_email_verified",
        "is_phone_verified",
        "country_code",
    )
    search_fields = ("email", "phone")

    
@admin.register(UserProfile)
class UserProfileAdmin(admin.ModelAdmin):
    model = UserProfile
    list_display = ("user", "first_name", "last_name")
    search_fields = ("user__email", "user__phone")
