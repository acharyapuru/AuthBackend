from django.db import models
from django.db.models import Q

class UserQuerySet(models.QuerySet):
    def active(self) -> models.QuerySet:
        return self.filter(is_active=True)

    def inactive(self) -> models.QuerySet:
        return self.filter(is_active=False)

    def phone_verified(self) -> models.QuerySet:
        return self.filter(is_phone_verified=True)

    def email_verified(self) -> models.QuerySet:
        return self.filter(is_email_verified=True)

    def staff(self) -> models.QuerySet:
        return self.filter(is_staff=True)

    def superuser(self) -> models.QuerySet:
        return self.filter(is_superuser=True)
    
    def email_user(self) -> models.QuerySet:
        return self.filter(email__isnull=False, is_email_verified=True)
    
    def phone_user(self) -> models.QuerySet:     
        return self.filter(phone__isnull=False, is_phone_verified=True)
    
    def find_by_email(self, email) -> models.QuerySet:
        try:
            return self.get(email=email)
        except self.model.DoesNotExist:
            return None
        
    def find_by_phone(self, phone) -> models.QuerySet:
        try:
            return self.get(phone=phone)
        except self.model.DoesNotExist:
            return None


class PseudoUserQuerySet(models.QuerySet):
    def email_verified(self) -> models.QuerySet:
        return self.filter(is_email_verified=True, email__isnull=False)
    
    def phone_verified(self) -> models.QuerySet:
        return self.filter(is_phone_verified=True, phone__isnull=False)
    
    def email_not_verified(self) -> models.QuerySet:
        return self.filter(is_email_verified=False, email__isnull=False)
    
    def phone_not_verified(self) -> models.QuerySet:
        return self.filter(is_phone_verified=False, phone__isnull=False)
    
    def verified(self) -> models.QuerySet:
        return self.filter(
            Q(is_email_verified=True, email__isnull=False) | Q(is_phone_verified=True, phone__isnull=False)
        )
    
    def unverified(self) -> models.QuerySet:
        return self.filter(
            Q(is_email_verified=False, email__isnull=False) | Q(is_phone_verified=False, phone__isnull=False)
        )
    
    def find_by_email(self, email) -> models.QuerySet:
        try:
            return self.get(email=email)
        except self.model.DoesNotExist:
            return None
        
    def find_by_phone(self, phone) -> models.QuerySet:
        try:
            return self.get(phone=phone)
        except self.model.DoesNotExist:
            return None