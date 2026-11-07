from rest_framework import serializers
from trust.models import PolicyConfig, TrustScoreRecord


class TrustScoreRecordSerializer(serializers.ModelSerializer):
    node_name = serializers.CharField(source="node.name", read_only=True)

    class Meta:
        model = TrustScoreRecord
        fields = [
            "id",
            "node",
            "node_name",
            "score",
            "previous_score",
            "rules_fired",
            "policy_version",
            "computed_at",
        ]
        read_only_fields = fields


class PolicyConfigSerializer(serializers.ModelSerializer):
    changed_by_username = serializers.CharField(source="changed_by.username", read_only=True)

    class Meta:
        model = PolicyConfig
        fields = [
            "version",
            "values",
            "changed_by_username",
            "changed_at",
            "change_reason",
        ]
        read_only_fields = ["version", "changed_by_username", "changed_at"]


class PolicyCreateSerializer(serializers.Serializer):
    values = serializers.DictField(required=True)
    change_reason = serializers.CharField(max_length=500, min_length=5, required=True)

