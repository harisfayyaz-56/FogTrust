from rest_framework import serializers

from .models import Heartbeat


class HeartbeatSerializer(serializers.ModelSerializer):
    node = serializers.UUIDField(source="node_id", read_only=True)
    nonce_prefix = serializers.SerializerMethodField()

    class Meta:
        model = Heartbeat
        fields = ["id", "node", "counter", "nonce_prefix", "sent_at", "received_at", "reported_load", "accepted", "reason_code"]
        read_only_fields = fields

    def get_nonce_prefix(self, obj) -> str:
        return obj.nonce[:4]  # enough to match a log line; the full nonce is never shown


class HeartbeatQuerySerializer(serializers.Serializer):
    # A ChoiceField, not a BooleanField: DRF reads a missing BooleanField in a query string as False,
    # which would silently hide every accepted heartbeat.
    accepted = serializers.ChoiceField(choices=["true", "false"], required=False)
    reason_code = serializers.RegexField(r"^[A-Z][A-Z0-9_]{0,47}$", required=False)