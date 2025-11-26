"""Custom RBAC permission class mapping HTTP methods to AccessRule flags."""

from django.conf import settings
from rest_framework import permissions

from .models import AccessRule


class RBACPermission(permissions.BasePermission):
    """Check access based on AccessRule for the view's business_element.

    If ``settings.ALLOW_SUPERUSER_BYPASS`` is True and the authenticated user is
    a Django superuser, all permission checks are short-circuited to allow the
    request. By default, this flag is False and superusers are subject to the
    same RBAC rules as regular users.
    """

    message = "You do not have permission to perform this action on this resource."

    def has_permission(self, request, view) -> bool:
        # Optional superuser bypass controlled by settings.ALLOW_SUPERUSER_BYPASS.
        if self._has_superuser_bypass(request):
            return True

        element_key = getattr(view, "business_element", None)
        if not element_key:
            return False

        user = getattr(request, "user", None)
        if not user or not getattr(user, "is_authenticated", False):
            return False

        rule = self._get_rule(user, element_key)
        if not rule:
            return False

        if request.method in permissions.SAFE_METHODS:
            return rule.can_read_all or rule.can_read_own
        if request.method == "POST":
            return rule.can_create
        if request.method in ("PUT", "PATCH"):
            return rule.can_update_all or rule.can_update_own
        if request.method == "DELETE":
            return rule.can_delete_all or rule.can_delete_own
        return False

    def has_object_permission(self, request, view, obj) -> bool:
        # Apply the same bypass at object level so superusers aren't blocked
        # by per-object "own vs all" checks when bypass is enabled.
        if self._has_superuser_bypass(request):
            return True

        user = getattr(request, "user", None)
        element_key = getattr(view, "business_element", None)
        if not element_key:
            return False

        rule = self._get_rule(user, element_key)
        if not rule:
            return False

        if request.method in permissions.SAFE_METHODS:
            return rule.can_read_all or (rule.can_read_own and self._is_owner(obj, request))
        if request.method in ("PUT", "PATCH"):
            return rule.can_update_all or (rule.can_update_own and self._is_owner(obj, request))
        if request.method == "DELETE":
            return rule.can_delete_all or (rule.can_delete_own and self._is_owner(obj, request))
        return False

    @staticmethod
    def _is_owner(obj, request) -> bool:
        owner = getattr(obj, "owner", None)
        return bool(owner and owner == request.user)

    @staticmethod
    def _has_superuser_bypass(request) -> bool:
        """Return True if superuser bypass is enabled and the user is a superuser."""

        user = getattr(request, "user", None)
        return (
                user is not None
                and getattr(user, "is_authenticated", False)
                and getattr(settings, "ALLOW_SUPERUSER_BYPASS", False)
                and getattr(user, "is_superuser", False)
        )

    @staticmethod
    def _get_rule(user, element_key):
        """Fetch the AccessRule for the given user and business element.

        Uses getattr to avoid static-analysis issues when the concrete User
        model adds a ``role`` FK that the generic AbstractBaseUser type
        does not declare.
        """
        role = getattr(user, "role", None)
        if role is None:
            return None
        try:
            return AccessRule.objects.select_related("role", "element").get(
                role=role, element__key=element_key
            )
        except AccessRule.DoesNotExist:
            return None


__all__ = ["RBACPermission"]
