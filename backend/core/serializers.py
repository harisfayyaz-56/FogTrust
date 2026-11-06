"""
Base serializer for every request body and query string.

The contract says unknown fields are rejected (docs/api-contract.md, section 1).
DRF silently ignores them by default, which hides typos and lets clients send
fields the server never meant to accept. StrictSerializer turns that into a
VALIDATION_ERROR without echoing the unknown names back.
"""

from collections.abc import Mapping

from rest_framework import serializers
from rest_framework.settings import api_settings


class StrictSerializer(serializers.Serializer):
    default_error_messages = {
        "not_object": "Expected a JSON object.",
        "unknown_fields": "Unknown fields are not allowed.",
    }

    def to_internal_value(self, data):
        if not isinstance(data, Mapping):
            raise serializers.ValidationError(
                {api_settings.NON_FIELD_ERRORS_KEY: [self.error_messages["not_object"]]}, code="not_object"
            )
        unknown = set(data) - set(self.fields)
        if unknown:
            raise serializers.ValidationError(
                {api_settings.NON_FIELD_ERRORS_KEY: [self.error_messages["unknown_fields"]]}, code="unknown_fields"
            )
        return super().to_internal_value(data)
