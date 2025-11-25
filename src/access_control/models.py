"""RBAC models: Role, BusinessElement, and AccessRule."""

from django.db import models


class Role(models.Model):
    """Represents a user's role in the RBAC system."""

    name = models.CharField(max_length=50, unique=True)
    description = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.name


class BusinessElement(models.Model):
    """Domain element guarded by RBAC rules (e.g., 'article', 'access_rule')."""

    key = models.CharField(max_length=50, unique=True)
    description = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.key


class AccessRule(models.Model):
    """Permission flags binding a Role to a BusinessElement."""

    role = models.ForeignKey(Role, on_delete=models.CASCADE, related_name="access_rules")
    element = models.ForeignKey(BusinessElement, on_delete=models.CASCADE, related_name="rules")

    can_read_own = models.BooleanField(default=False)
    can_read_all = models.BooleanField(default=False)
    can_create = models.BooleanField(default=False)
    can_update_own = models.BooleanField(default=False)
    can_update_all = models.BooleanField(default=False)
    can_delete_own = models.BooleanField(default=False)
    can_delete_all = models.BooleanField(default=False)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = ("role", "element")

    def __str__(self) -> str:  # pragma: no cover - trivial
        return f"{self.role.name} -> {self.element.key}"


__all__ = ["Role", "BusinessElement", "AccessRule"]
