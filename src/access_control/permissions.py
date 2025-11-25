"""Custom RBAC permission class mapping HTTP methods to AccessRule flags."""

from rest_framework import permissions

from .models import AccessRule


class RBACPermission(permissions.BasePermission):
    """Check access based on AccessRule for the view's business_element."""

    message = "You do not have permission to perform this action on this resource."

    def has_permission(self, request, view) -> bool:
        element_key = getattr(view, "business_element", None)
        if not element_key:
            return False

        if not request.user or not request.user.is_authenticated:
            return False

        rule = self._get_rule(request.user.role_id, element_key)
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
        element_key = getattr(view, "business_element", None)
        if not element_key:
            return False

        rule = self._get_rule(request.user.role_id, element_key)
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
    def _get_rule(role_id, element_key):
        try:
            return AccessRule.objects.select_related("role", "element").get(
                role_id=role_id, element__key=element_key
            )
        except AccessRule.DoesNotExist:
            return None


__all__ = ["RBACPermission"]
