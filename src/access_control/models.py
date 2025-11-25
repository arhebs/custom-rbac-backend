"""RBAC models: Role placeholder; other models arrive in later steps."""

from django.db import models


class Role(models.Model):
    """Represents a user's role in the RBAC system."""

    name = models.CharField(max_length=50, unique=True)
    description = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.name


__all__ = ["Role"]
