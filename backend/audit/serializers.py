from rest_framework import serializers

from core.serializers import StrictSerializer

from .models import AuditEvent


class AuditEventSerializer(serializers.ModelSerializer):
    class Meta:
        model = AuditEvent
        fields = [
            "sequence",
            "event_id",
            "timestamp",
            "actor_type",
            "actor_id",
            "actor_role",
            "action",
            "target_type",
            "target_id",
            "outcome",
            "reason_code",
            "request_id",
            "source_ip",
            "details",
            "prev_hash",
            "hash",
        ]
        read_only_fields = fields


class AuditQuerySerializer(StrictSerializer):
    """Allowed query parameters for GET /audit/. Anything else is rejected."""

    action = serializers.RegexField(r"^[a-z_.]{1,64}$", required=False)
    actor = serializers.CharField(max_length=64, required=False)
    outcome = serializers.ChoiceField(choices=AuditEvent.Outcome.choices, required=False)
    reason_code = serializers.RegexField(r"^[A-Z0-9_]{1,48}$", required=False)
    since = serializers.DateTimeField(required=False)
    until = serializers.DateTimeField(required=False)
    page = serializers.IntegerField(min_value=1, required=False)
    page_size = serializers.IntegerField(min_value=1, max_value=100, required=False)

    def validate(self, attrs):
        if attrs.get("since") and attrs.get("until") and attrs["since"] > attrs["until"]:
            raise serializers.ValidationError({"until": ["Must be later than 'since'."]})
        return attrs
