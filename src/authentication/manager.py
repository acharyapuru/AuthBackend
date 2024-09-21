from typing import Dict, Type
from django.contrib.auth.base_user import BaseUserManager
from django.db import models
from .queryset import UserQuerySet, PseudoUserQuerySet


class CustomUserManager(BaseUserManager):

    use_in_migrations = True
    
    def _create_user(self, password: str, email: str = None, phone:str = None, **extra_fields) -> Type[models.Model]:
        
        email = self.normalize_email(email)
        user = self.model(phone=phone, email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def _create_superuser(self, email: str, password: str, **extra_fields) -> Type[models.Model]:
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user
    
    def create_user(
            self,
            phone : str = None,
            email: str = None, 
            password: str = None, 
            **extra_fields
    ) -> Type[models.Model]:
        
        extra_fields.setdefault('is_staff', False)
        extra_fields.setdefault('is_superuser', False)

        return self._create_user(password=password, email=email, **extra_fields)
    

    def create_superuser(self, email: str, password: str, **extra_fields) -> Type[models.Model]:
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('is_active', True)
        extra_fields.setdefault('is_phone_verified', False)
        extra_fields.setdefault('is_email_verified', True)
        return self._create_superuser(email, password, **extra_fields)
    


class UserFilterManager(models.Manager.from_queryset(UserQuerySet)):
    pass

class PseudoUserManager(models.Manager.from_queryset(PseudoUserQuerySet)):
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)