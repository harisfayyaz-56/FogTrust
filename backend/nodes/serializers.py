"""
Request and response shapes for enrollment, tokens and nodes (docs/api-contract.md, section 5.4).

Every request serializer extends StrictSerializer, so unknown fields are rejected, and every
field has a length cap, so oversized values are refused before any work is done.
"""

import unicodedata

from django.conf import settings
from rest_framework import serializers

from core.serializers import StrictSerializer

from .models import NODE_NAME_PATTERN, EnrollmentToken, Node


def no_control_characters(value: str) -> str:
    """Reject newlines, tabs and other invisible characters (category C*), which can forge log lines."""
    if any(unicodedata.category(char).startswith("C") for char in value):
        raise serializers.ValidationError("Control characters are not allowed.")
    return value


# ------------------------------------------------------------------ requests


class EnrollmentTokenCreateSerializer(StrictSerializer):
    label = serializers.CharField(min_length=1, max_length=64, validators=[no_control_characters])
    expires_in_minutes = serializers.IntegerField(
        min_value=1, max_value=settings.ENROLLMENT_TOKEN_MAX_MINUTES, required=False,
        default=settings.ENROLLMENT_TOKEN_DEFAULT_MINUTES,
    )


class EnrollSerializer(StrictSerializer):
    """
    Shape checks only. Whether the token is genuine, the key is a real Ed25519 key and the
    proof verifies are decided in services.enroll_node, in the contract's order, with the
    contract's error codes (so `public_key` is only length-capped here).
    """

    enrollment_token = serializers.RegexField(r"^[A-Za-z0-9_-]{20,128}$")
    name = serializers.RegexField(NODE_NAME_PATTERN)
    public_key = serializers.CharField(min_length=1, max_length=64)
    capacity = serializers.IntegerField(min_value=1, max_value=100, required=False, default=4)
    proof = serializers.CharField(min_length=1, max_length=128)


class RevokeSerializer(StrictSerializer):
    reason = serializers.CharField(min_length=10, max_length=500, validators=[no_control_characters])
    # Missing or wrong is CONFIRMATION_REQUIRED (decided in the view), not a validation error.
    confirm_name = serializers.CharField(max_length=64, required=False, allow_blank=True, trim_whitespace=False)


class NodeQuerySerializer(StrictSerializer):
    status = serializers.ChoiceField(choices=Node.Status.choices, required=False)
    min_trust = serializers.IntegerField(min_value=0, max_value=100, required=False)
    search = serializers.CharField(max_length=64, required=False, validators=[no_control_characters])
    page = serializers.IntegerField(min_value=1, required=False)
    page_size = serializers.IntegerField(min_value=1, max_value=100, required=False)


class TokenQuerySerializer(StrictSerializer):
    status = serializers.ChoiceField(choices=EnrollmentToken.State.choices, required=False)
    page = serializers.IntegerField(min_value=1, required=False)
    page_size = serializers.IntegerField(min_value=1, max_value=100, required=False)


# ----------------------------------------------------------------- responses


class NodeSerializer(serializers.ModelSerializer):
    """Never includes the public key itself: the fingerprint identifies it (contract 5.4)."""

    revoked_by = serializers.SlugRelatedField(slug_field="username", read_only=True)

    class Meta:
        model = Node
        fields = [
            "id",
            "name",
            "status",
            "key_fingerprint",
            "capacity",
            "current_load",
            "trust_score",
            "last_seen_at",
            "enrolled_at",
            "revoked_at",
            "revoked_by",
            "revoke_reason",
            "revoke_source",
        ]
        read_only_fields = fields

    def to_representation(self, instance):
        data = super().to_representation(instance)
        # Contract: null (not an empty string) while the node is active.
        data["revoke_reason"] = data["revoke_reason"] or None
        data["revoke_source"] = data["revoke_source"] or None
        return data


class EnrollmentTokenSerializer(serializers.ModelSerializer):
    """Lists tokens WITHOUT their value: only the hash is stored, so the value cannot be shown again."""

    status = serializers.SerializerMethodField()
    created_by = serializers.SlugRelatedField(slug_field="username", read_only=True)
    used_by_node = serializers.SlugRelatedField(slug_field="name", read_only=True)

    class Meta:
        model = EnrollmentToken
        fields = ["id", "label", "status", "created_by", "created_at", "expires_at", "used_at", "used_by_node", "cancelled_at"]
        read_only_fields = fields

    def get_status(self, obj) -> str:
        return str(obj.state())
