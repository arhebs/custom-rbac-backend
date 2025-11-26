"""Serializers for access control resources."""

from rest_framework import serializers

from .models import AccessRule, BusinessElement, Role


class AccessRuleSerializer(serializers.ModelSerializer):
    """Serialize AccessRule entries for the admin interface.

    Uses human-friendly identifiers (role name and business element key) instead
    of numeric IDs to simplify reading/writing rules via the API.
    """

    role = serializers.SlugRelatedField(slug_field="name", queryset=Role.objects.all())
    element = serializers.SlugRelatedField(slug_field="key", queryset=BusinessElement.objects.all())

    class Meta:
        """Expose AccessRule flags with role/element slugs; timestamps are read-only."""

        model = AccessRule
        fields = [
            "id",
            "role",
            "element",
            "can_read_own",
            "can_read_all",
            "can_create",
            "can_update_own",
            "can_update_all",
            "can_delete_own",
            "can_delete_all",
            "created_at",
            "updated_at",
        ]
        read_only_fields = ["id", "created_at", "updated_at"]

    def validate(self, attrs):
        """Prevent duplicate (role, element) pairs with a friendly error."""
        role = attrs.get("role") or getattr(self.instance, "role", None)
        element = attrs.get("element") or getattr(self.instance, "element", None)
        if role and element:
            qs = AccessRule.objects.filter(role=role, element=element)
            if self.instance:
                qs = qs.exclude(pk=self.instance.pk)
            if qs.exists():
                raise serializers.ValidationError("Rule for this role and element already exists.")
        return attrs


__all__ = ["AccessRuleSerializer"]
