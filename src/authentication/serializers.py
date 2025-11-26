"""Serializers for authentication flows (register, login, profile)."""

from typing import cast

from django.contrib.auth import get_user_model
from rest_framework import serializers

from access_control.models import Role
from rest_framework.exceptions import AuthenticationFailed

from .managers import UserManager

User = get_user_model()


class RegisterSerializer(serializers.Serializer):
    """Validate and create a user with the default 'User' role."""

    email = serializers.EmailField()
    password = serializers.CharField(write_only=True, min_length=8)
    repeat_password = serializers.CharField(write_only=True, min_length=8)
    # In the original Russian task, "имя" (first name) is required, while
    # фамилия/отчество (last name/patronymic) are optional.
    first_name = serializers.CharField(required=True, allow_blank=False)
    last_name = serializers.CharField(required=False, allow_blank=True)
    patronymic = serializers.CharField(required=False, allow_blank=True)

    @staticmethod
    def validate_email(value):
        """Ensure email is unique before creation."""
        if User.objects.filter(email=value).exists():
            raise serializers.ValidationError("Email already in use")
        return value

    def validate(self, attrs):
        """Ensure provided passwords match before creation."""
        if attrs.get("password") != attrs.get("repeat_password"):
            raise serializers.ValidationError("Passwords do not match")
        return attrs

    def create(self, validated_data):
        """Create a user with the default 'User' role and hashed password."""
        validated_data.pop("repeat_password")
        role = Role.objects.filter(name__iexact="User").first()
        if role is None:
            raise serializers.ValidationError("Default role 'User' not configured")
        manager = cast(UserManager, User.objects)
        user = manager.create_user(role=role, **validated_data)
        return user


class LoginSerializer(serializers.Serializer):
    """Authenticate a user via email/password using bcrypt verification."""

    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)

    def validate(self, attrs):
        """Authenticate credentials and attach the user to validated_data."""
        email = attrs.get("email")
        password = attrs.get("password")
        try:
            user = User.objects.select_related("role").get(email=email)
        except User.DoesNotExist:
            raise AuthenticationFailed("Invalid credentials")

        if not user.is_active:
            raise AuthenticationFailed("User is inactive")

        if not UserManager.verify_password(user, password):
            raise AuthenticationFailed("Invalid credentials")

        attrs["user"] = user
        return attrs


class UserDetailSerializer(serializers.ModelSerializer):
    """Read-only user profile payload for responses."""

    role = serializers.CharField(source="role.name")

    class Meta:
        """Expose basic identity fields and role name."""
        model = User
        fields = [
            "id",
            "email",
            "first_name",
            "last_name",
            "patronymic",
            "role",
        ]
        read_only_fields = fields


class ProfileUpdateSerializer(serializers.ModelSerializer):
    """Patchable fields for /auth/me updates."""

    class Meta:
        """Allow partial updates of profile name fields."""
        model = User
        fields = ["first_name", "last_name", "patronymic"]
        extra_kwargs = {field: {"required": False, "allow_blank": True} for field in fields}

    def validate(self, attrs):
        """Disallow attempts to change email via this endpoint.

        Any payload that includes an 'email' field should be rejected with a
        validation error rather than silently ignored, to make the restriction
        explicit to API consumers.
        """
        if "email" in getattr(self, "initial_data", {}):
            raise serializers.ValidationError("Email cannot be updated via this endpoint")
        return super().validate(attrs)
