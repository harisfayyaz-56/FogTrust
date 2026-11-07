"""
GET /api/v1/decisions/  (any signed-in role)  -- the dashboard's evidence view.

Filters: ?subject_type= ?subject_id= ?decision= ?reason_code= ?since= ?until= (ISO 8601)
Newest first, paginated. Evidence is redacted when the Decision is written, so what a
viewer sees here never contains keys, tokens, signatures or plaintext.
"""

from rest_framework import serializers
from rest_framework.generics import ListAPIView

from accounts.permissions import require

from .models import Decision
from .serializers import StrictSerializer


class DecisionSerializer(serializers.ModelSerializer):
    class Meta:
        model = Decision
        fields = [
            "decision_id",
            "subject_type",
            "subject_id",
            "decision",
            "reason_code",
            "explanation",
            "rules_fired",
            "evidence",
            "engine_name",
            "engine_version",
            "policy_version",
            "thresholds",
            "request_id",
            "decided_at",
            "latency_ms",
        ]
        read_only_fields = fields


class DecisionQuerySerializer(StrictSerializer):
    subject_type = serializers.ChoiceField(choices=Decision.SubjectType.choices, required=False)
    subject_id = serializers.RegexField(r"^[A-Za-z0-9_.:-]{1,64}$", required=False)
    decision = serializers.ChoiceField(choices=Decision.Verdict.choices, required=False)
    reason_code = serializers.RegexField(r"^[A-Z0-9_]{1,48}$", required=False)
    since = serializers.DateTimeField(required=False)
    until = serializers.DateTimeField(required=False)
    page = serializers.IntegerField(min_value=1, required=False)
    page_size = serializers.IntegerField(min_value=1, max_value=100, required=False)

    def validate(self, attrs):
        if attrs.get("since") and attrs.get("until") and attrs["since"] > attrs["until"]:
            raise serializers.ValidationError({"until": ["Must be later than 'since'."]})
        return attrs


class DecisionListView(ListAPIView):
    permission_classes = [require("decisions.view")]
    serializer_class = DecisionSerializer

    def get_queryset(self):
        query = DecisionQuerySerializer(data=self.request.query_params)
        query.is_valid(raise_exception=True)
        filters = query.validated_data

        queryset = Decision.objects.all()
        for name in ("subject_type", "subject_id", "decision", "reason_code"):
            if name in filters:
                queryset = queryset.filter(**{name: filters[name]})
        if "since" in filters:
            queryset = queryset.filter(decided_at__gte=filters["since"])
        if "until" in filters:
            queryset = queryset.filter(decided_at__lte=filters["until"])
        return queryset
