from rest_framework import status
from rest_framework.generics import ListAPIView
from rest_framework.response import Response
from rest_framework.views import APIView

from accounts.permissions import require
from trust.models import PolicyConfig, TrustScoreRecord
from trust.serializers import PolicyConfigSerializer, PolicyCreateSerializer, TrustScoreRecordSerializer
from trust.services import create_policy


class NodeTrustHistoryView(ListAPIView):
    permission_classes = [require("trust.view")]
    serializer_class = TrustScoreRecordSerializer

    def get_queryset(self):
        node_id = self.kwargs.get("node_id")
        return TrustScoreRecord.objects.filter(node_id=node_id).order_by("-computed_at")


class PolicyView(APIView):
    def get_permissions(self):
        if self.request.method == "POST":
            return [require("policy.change")()]
        return [require("policy.view")()]

    def get(self, request):
        policy = PolicyConfig.current()
        return Response(PolicyConfigSerializer(policy).data)

    def post(self, request):
        serializer = PolicyCreateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        policy = create_policy(
            admin_user=request.user,
            values=serializer.validated_data["values"],
            change_reason=serializer.validated_data["change_reason"],
            request=request,
        )

        return Response(PolicyConfigSerializer(policy).data, status=status.HTTP_201_CREATED)
