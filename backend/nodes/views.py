"""
Enrollment tokens, enrollment, node listing and revocation (docs/api-contract.md, section 5.4).

    POST /api/v1/enrollment-tokens/              admin   create a one-time token
    GET  /api/v1/enrollment-tokens/              admin   list tokens (never their values)
    POST /api/v1/enrollment-tokens/{id}/cancel/  admin   cancel an unused token
    POST /api/v1/nodes/enroll/                   node + token, throttled   FR-1
    GET  /api/v1/nodes/                          any role  ?status= ?min_trust= ?search=
    GET  /api/v1/nodes/{id}/                     any role
    POST /api/v1/nodes/{id}/revoke/              admin, needs confirmation   FR-6
"""

import uuid

from django.utils import timezone
from rest_framework import serializers, status
from rest_framework.exceptions import ParseError, UnsupportedMediaType
from rest_framework.generics import ListAPIView
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.throttling import ScopedRateThrottle
from rest_framework.views import APIView

from accounts.permissions import require
from core.errors import APIError, ErrorCode
from core.pagination import StandardPagination
from django.conf import settings

from .models import EnrollmentToken, Node
from .serializers import (
    EnrollmentTokenCreateSerializer,
    EnrollmentTokenSerializer,
    EnrollSerializer,
    NodeQuerySerializer,
    NodeSerializer,
    RevokeSerializer,
    TokenQuerySerializer,
)
from .server_keys import server_public_key_b64
from .services import (
    audit_enroll_rejection,
    cancel_enrollment_token,
    create_enrollment_token,
    enroll_node,
    reject_unconfirmed_revocation,
    revoke_node,
)


def _parse_uuid(value: str) -> uuid.UUID:
    """A malformed id is the same as an unknown one (data-model.md section 6): NOT_FOUND."""
    try:
        return uuid.UUID(value)
    except ValueError:
        raise APIError(ErrorCode.NOT_FOUND) from None


# ------------------------------------------------------------------------- tokens


class EnrollmentTokenListCreateView(APIView):
    permission_classes = [require("tokens.manage")]

    def get(self, request):
        query = TokenQuerySerializer(data=request.query_params)
        query.is_valid(raise_exception=True)
        queryset = EnrollmentToken.objects.select_related("created_by", "used_by_node").order_by("-created_at")
        wanted = query.validated_data.get("status")
        if wanted:
            now = timezone.now()
            queryset = {
                EnrollmentToken.State.USED: queryset.filter(used_at__isnull=False),
                EnrollmentToken.State.CANCELLED: queryset.filter(used_at__isnull=True, cancelled_at__isnull=False),
                EnrollmentToken.State.EXPIRED: queryset.filter(
                    used_at__isnull=True, cancelled_at__isnull=True, expires_at__lte=now
                ),
                EnrollmentToken.State.PENDING: queryset.filter(
                    used_at__isnull=True, cancelled_at__isnull=True, expires_at__gt=now
                ),
            }[wanted]
        paginator = StandardPagination()
        page = paginator.paginate_queryset(queryset, request, view=self)
        return paginator.get_paginated_response(EnrollmentTokenSerializer(page, many=True).data)

    def post(self, request):
        serializer = EnrollmentTokenCreateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        token, raw_token = create_enrollment_token(
            label=serializer.validated_data["label"],
            expires_in_minutes=serializer.validated_data["expires_in_minutes"],
            created_by=request.user,
            request=request,
        )
        # The raw token appears in this response and nowhere else, ever.
        response = Response(
            {"id": str(token.id), "label": token.label, "token": raw_token, "expires_at": token.expires_at},
            status=status.HTTP_201_CREATED,
        )
        response["Cache-Control"] = "no-store"
        return response


class EnrollmentTokenCancelView(APIView):
    permission_classes = [require("tokens.manage")]

    def post(self, request, token_id):
        token = EnrollmentToken.objects.filter(pk=_parse_uuid(token_id)).first()
        if token is None:
            raise APIError(ErrorCode.NOT_FOUND)
        token = cancel_enrollment_token(token, by=request.user, request=request)
        return Response(EnrollmentTokenSerializer(token).data)


# ---------------------------------------------------------------------- enrollment


class NodeEnrollView(APIView):
    """
    FR-1. Public (a new node has no credentials yet), so it is the most exposed endpoint:
    throttled per client, body capped at ENROLL_MAX_BODY_BYTES, and every refusal audited.
    """

    authentication_classes = []  # no session, so CSRF does not apply (contract section 2.2)
    permission_classes = [AllowAny]
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = "enroll"

    def post(self, request):
        self._enforce_body_limit(request)
        try:
            data = request.data
        except ParseError:
            audit_enroll_rejection(request, ErrorCode.MALFORMED_REQUEST)
            raise
        except UnsupportedMediaType:
            audit_enroll_rejection(request, ErrorCode.UNSUPPORTED_MEDIA_TYPE)
            raise
        serializer = EnrollSerializer(data=data)
        try:
            serializer.is_valid(raise_exception=True)
        except serializers.ValidationError as exc:
            fields = sorted(exc.detail) if isinstance(exc.detail, dict) else []  # names only, never values
            audit_enroll_rejection(request, ErrorCode.VALIDATION_ERROR, {"fields": fields})
            raise

        fields = serializer.validated_data
        node = enroll_node(
            raw_token=fields["enrollment_token"],
            name=fields["name"],
            public_key=fields["public_key"],
            capacity=fields["capacity"],
            proof=fields["proof"],
            request=request,
        )
        response = Response(
            {
                "node_id": str(node.id),
                "name": node.name,
                "status": node.status,
                "capacity": node.capacity,
                "key_fingerprint": node.key_fingerprint,
                "enrolled_at": node.enrolled_at,
                # Where nodes encrypt results to. null until the admin runs generate_server_key.
                "server_public_key": server_public_key_b64(),
            },
            status=status.HTTP_201_CREATED,
        )
        response["Cache-Control"] = "no-store"
        return response

    @staticmethod
    def _enforce_body_limit(request) -> None:
        limit = settings.ENROLL_MAX_BODY_BYTES
        declared = request.META.get("CONTENT_LENGTH", "")
        too_large = (declared.isdigit() and int(declared) > limit) or len(request.body) > limit
        if too_large:
            audit_enroll_rejection(request, ErrorCode.PAYLOAD_TOO_LARGE)
            raise APIError(ErrorCode.PAYLOAD_TOO_LARGE)


# ---------------------------------------------------------------------------- nodes


class NodeListView(ListAPIView):
    permission_classes = [require("nodes.view")]
    serializer_class = NodeSerializer

    def get_queryset(self):
        query = NodeQuerySerializer(data=self.request.query_params)
        query.is_valid(raise_exception=True)
        filters = query.validated_data

        queryset = Node.objects.select_related("revoked_by").order_by("name")
        if "status" in filters:
            queryset = queryset.filter(status=filters["status"])
        if "min_trust" in filters:
            queryset = queryset.filter(trust_score__gte=filters["min_trust"])
        if "search" in filters:
            queryset = queryset.filter(name__icontains=filters["search"])  # ORM: parameterised
        return queryset


class NodeDetailView(APIView):
    permission_classes = [require("nodes.view")]

    def get(self, request, node_id):
        node = Node.objects.select_related("revoked_by").filter(pk=_parse_uuid(node_id)).first()
        if node is None:
            raise APIError(ErrorCode.NOT_FOUND)
        return Response(NodeSerializer(node).data)


class NodeRevokeView(APIView):
    """FR-6. High-impact: admin only, and the admin must type the node's exact name."""

    permission_classes = [require("nodes.revoke")]

    def post(self, request, node_id):
        node = Node.objects.filter(pk=_parse_uuid(node_id)).first()
        if node is None:
            raise APIError(ErrorCode.NOT_FOUND)
        serializer = RevokeSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        if serializer.validated_data.get("confirm_name", "") != node.name:
            raise reject_unconfirmed_revocation(node, request=request)
        node = revoke_node(
            node, reason=serializer.validated_data["reason"], by=request.user, source=Node.RevokeSource.MANUAL, request=request
        )
        return Response(
            {
                "id": str(node.id),
                "status": node.status,
                "revoked_at": node.revoked_at,
                "revoked_by": request.user.get_username(),
                "revoke_reason": node.revoke_reason,
            }
        )
