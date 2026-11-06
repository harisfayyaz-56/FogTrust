from django.utils import timezone
from rest_framework.generics import ListAPIView
from rest_framework.response import Response
from rest_framework.views import APIView

from accounts.permissions import require
from core.errors import ErrorCode

from .models import AuditEvent
from .serializers import AuditEventSerializer, AuditQuerySerializer
from .services import log_event, verify_chain


class AuditEventListView(ListAPIView):
    """
    GET /api/v1/audit/  (admin only)
    Filters: ?action= ?actor= ?outcome= ?reason_code= ?since= ?until=  (ISO 8601)
    """

    permission_classes = [require("audit.view")]
    serializer_class = AuditEventSerializer

    def get_queryset(self):
        query = AuditQuerySerializer(data=self.request.query_params)
        query.is_valid(raise_exception=True)
        filters = query.validated_data

        queryset = AuditEvent.objects.all().order_by("-sequence")
        if "action" in filters:
            queryset = queryset.filter(action=filters["action"])
        if "actor" in filters:
            queryset = queryset.filter(actor_id=filters["actor"])
        if "outcome" in filters:
            queryset = queryset.filter(outcome=filters["outcome"])
        if "reason_code" in filters:
            queryset = queryset.filter(reason_code=filters["reason_code"])
        if "since" in filters:
            queryset = queryset.filter(timestamp__gte=filters["since"])
        if "until" in filters:
            queryset = queryset.filter(timestamp__lte=filters["until"])
        return queryset


class AuditVerifyView(APIView):
    """POST /api/v1/audit/verify/  (admin only). Recomputes the whole hash chain."""

    permission_classes = [require("audit.verify")]

    def post(self, request):
        report = verify_chain()
        log_event(
            "audit.verify",
            "success" if report.valid else "failure",
            request=request,
            target_type="audit_log",
            reason_code="" if report.valid else ErrorCode.AUDIT_CHAIN_BROKEN,
            details=report.as_dict(),
        )
        return Response({**report.as_dict(), "checked_at": timezone.now()})
