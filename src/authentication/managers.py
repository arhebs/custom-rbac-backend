"""Custom user manager handling bcrypt hashing and verification."""

import uuid

import bcrypt
from django.contrib.auth.base_user import BaseUserManager


class UserManager(BaseUserManager):
    """Manager to create users with bcrypt password hashes."""

    use_in_migrations = True

    def _create_user(self, email: str, password: str, **extra_fields):
        if not email:
            raise ValueError("The Email must be set")
        email = self.normalize_email(email)
        user = self.model(id=uuid.uuid4(), email=email, **extra_fields)
        user.password_hash = self.hash_password(password)
        user.save(using=self._db)
        return user

    def create_user(self, email: str, password: str | None = None, **extra_fields):
        """Create a regular user with bcrypt-hashed password."""
        extra_fields.setdefault("is_staff", False)
        extra_fields.setdefault("is_superuser", False)
        if password is None:
            raise ValueError("Password must be provided")
        return self._create_user(email, password, **extra_fields)

    def create_superuser(self, email: str, password: str, **extra_fields):
        """Create a superuser ensuring staff/superuser flags are set."""
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)
        extra_fields.setdefault("is_active", True)
        if not extra_fields.get("is_staff"):
            raise ValueError("Superuser must have is_staff=True.")
        if not extra_fields.get("is_superuser"):
            raise ValueError("Superuser must have is_superuser=True.")
        return self._create_user(email, password, **extra_fields)

    @staticmethod
    def hash_password(raw_password: str) -> str:
        """Hash a raw password using bcrypt and return the utf-8 string."""
        salt = bcrypt.gensalt()
        hashed = bcrypt.hashpw(raw_password.encode(), salt)
        return hashed.decode()

    @staticmethod
    def verify_password(user, raw_password: str) -> bool:
        """Verify raw password against stored bcrypt hash."""

        if not user.password_hash:
            return False
        return bcrypt.checkpw(raw_password.encode(), user.password_hash.encode("utf-8"))


__all__ = ["UserManager"]
