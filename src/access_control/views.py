"""ViewSets for access control administration."""

from rest_framework import viewsets

from core.response import BaseViewSet
from .models import AccessRule
from .permissions import RBACPermission
from .serializers import AccessRuleSerializer


class AccessRuleViewSet(BaseViewSet, viewsets.ModelViewSet):
    """CRUD endpoints for managing AccessRule entries."""

    serializer_class = AccessRuleSerializer
    permission_classes = [RBACPermission]
    business_element = "access_rule"
    queryset = AccessRule.objects.select_related("role", "element")

    def get_queryset(self):
        """Scope list results based on RBAC flags.

        - If the user can_read_all on access_rule, return all rules.
        - If the user only has can_read_own, return rules for their role.
        - Otherwise return an empty queryset.
        """
        user = self.request.user
        if not getattr(user, "is_authenticated", False):
            return AccessRule.objects.none()

        rule = self._get_rule(user)
        if not rule:
            return AccessRule.objects.none()

        base_qs = AccessRule.objects.select_related("role", "element")
        if rule.can_read_all:
            return base_qs
        if rule.can_read_own:
            # For the access_rule element, "own" is interpreted as rules for
            # the caller's role. We rely on the AccessRule used for the
            # permission check to identify that role, rather than accessing
            # a dynamic ``user.role`` attribute directly.
            return base_qs.filter(role=rule.role)
        return AccessRule.objects.none()

    def _get_rule(self, user):
        from .models import AccessRule as Rule

        role = getattr(user, "role", None)
        if role is None:
            return None

        try:
            return Rule.objects.get(role=role, element__key=self.business_element)
        except Rule.DoesNotExist:
            return None


__all__ = ["AccessRuleViewSet"]
