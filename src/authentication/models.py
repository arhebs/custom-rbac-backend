"""Custom User model using bcrypt-hashed passwords and RBAC role linkage.

Note: We intentionally avoid Django's built-in groups/permissions (no
PermissionsMixin) to comply with the project requirement to implement RBAC
exclusively via our own Role/AccessRule tables.
"""

import uuid
from typing import Optional, ClassVar

from django.contrib.auth.models import AbstractBaseUser
from django.db import models

from .managers import UserManager


class User(AbstractBaseUser):
    """Custom user identified by email with bcrypt password hashes."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    email = models.EmailField(unique=True)
    password_hash = models.CharField(max_length=128)
    first_name = models.CharField(max_length=150, blank=True)
    last_name = models.CharField(max_length=150, blank=True)
    patronymic = models.CharField(max_length=150, blank=True)
    role = models.ForeignKey("access_control.Role", on_delete=models.PROTECT, related_name="users")
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    is_superuser = models.BooleanField(default=False)
    date_joined = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS: ClassVar[list[str]] = []

    objects = UserManager()

    class Meta:
        """Default ordering shows newest users first."""
        ordering = ["-date_joined"]

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.email

    def set_password(self, raw_password: Optional[str]) -> None:  # type: ignore[override]
        """Override to ensure bcrypt hashing via manager utility."""

        if raw_password is None:
            self.password_hash = ""
        else:
            self.password_hash = UserManager.hash_password(raw_password)

    def check_password(self, raw_password: Optional[str]) -> bool:  # type: ignore[override]
        """Delegate to bcrypt verification helper."""

        if raw_password is None:
            return False
        return UserManager.verify_password(self, raw_password)


__all__ = ["User"]
