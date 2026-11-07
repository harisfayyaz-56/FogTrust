from rest_framework import serializers
from tasks.models import Task


class TaskSubmitSerializer(serializers.ModelSerializer):
    class Meta:
        model = Task
        fields = ["id", "task_type", "payload", "priority", "status", "created_at"]
        read_only_fields = ["id", "status", "created_at"]

    def validate_task_type(self, value):
        if value not in Task.TASK_TYPE_ALLOWLIST:
            raise serializers.ValidationError(
                f"Task type '{value}' not allowed. Must be one of: {Task.TASK_TYPE_ALLOWLIST}"
            )
        return value

    def validate_payload(self, value):
        if not isinstance(value, dict):
            raise serializers.ValidationError("Payload must be a JSON object.")
        return value


class TaskDetailSerializer(serializers.ModelSerializer):
    assigned_node_name = serializers.CharField(source="assigned_node.name", read_only=True)

    class Meta:
        model = Task
        fields = [
            "id",
            "task_type",
            "payload",
            "priority",
            "status",
            "assigned_node",
            "assigned_node_name",
            "attempts",
            "max_attempts",
            "idempotency_key",
            "created_at",
            "assigned_at",
            "completed_at",
        ]
        read_only_fields = fields

