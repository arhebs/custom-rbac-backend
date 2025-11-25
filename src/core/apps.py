"""App configuration for the core project utilities."""

from django.apps import AppConfig


class CoreConfig(AppConfig):
    """Core app holds shared settings, URLs, and middleware."""

    default_auto_field = "django.db.models.BigAutoField"
    name = "core"
