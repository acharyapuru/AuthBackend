from django.db.models.signals import post_save
from django.dispatch import receiver
from .models import User, PseudoUser, UserProfile

@receiver(post_save, sender=User)
def delete_pseudo_user_after_user_creation(sender, instance, created, **kwargs):

    email = instance.email
    phone = instance.phone
    
    verification_field = "email" if email else "phone"
    verification_value = email or phone
    verification_field_key = f"is_{verification_field}_verified"
    if created:
        try:
            pseudo_user = PseudoUser.objects.get(**{verification_field: verification_value})
            setattr(instance, verification_field_key, getattr(pseudo_user, verification_field_key))
            pseudo_user.delete()
            instance.is_active = True
            instance.save()
        except PseudoUser.DoesNotExist:
            pass

@receiver(post_save, sender=User)
def create_user_profile(sender, instance, created, **kwargs):
    if created:
        UserProfile.objects.create(user=instance)
        