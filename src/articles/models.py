"""Article model demonstrating own vs all permissions."""

from django.conf import settings
from django.db import models


class Article(models.Model):
    """Simple article with owner to support RBAC own/all checks."""

    title = models.CharField(max_length=255)
    content = models.TextField()
    owner = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="articles")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.title


__all__ = ["Article"]
