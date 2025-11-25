"""Serializers for Article CRUD with standard envelope support."""

from rest_framework import serializers

from .models import Article


class ArticleSerializer(serializers.ModelSerializer):
    owner = serializers.PrimaryKeyRelatedField(read_only=True)

    class Meta:
        """Expose article fields while keeping ownership and timestamps read-only."""
        model = Article
        fields = ["id", "title", "content", "owner", "created_at", "updated_at"]
        read_only_fields = ["id", "owner", "created_at", "updated_at"]


__all__ = ["ArticleSerializer"]
