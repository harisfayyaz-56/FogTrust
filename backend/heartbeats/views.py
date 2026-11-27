"""
POST /node-api/heartbeat/  (FR-2, T2)   and   GET /nodes/{id}/heartbeats/

The view is thin on purpose. All the security decisions are made by fogtrust_crypto.verify_heartbeat;
this file only (1) refuses oversized bodies before reading them, (2) feeds the engine the raw bytes,
(3) stores what happened, and (4) turns a denial into the standard error.

What is stored, and where:
  accepted   -> a Heartbeat row, Node.last_seen_at. No Decision and no audit event (they would
                drown the evidence view: one per node every few seconds).
  rejected   -> a Decision (the evidence view), an audit event `heartbeat.rejected`, and, if the node
                is enrolled, a rejected Heartbeat row for its history.
"""

import uuid

from django.utils import timezone
from rest_framework.generics import ListAPIView
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView

from accounts.permissions import require
from audit.services import log_event
from core.decisions import record_decision_dict
from core.errors import APIError, ErrorCode
from core.pagination import StandardPagination
from fogtrust_crypto.heartbeat import MAX_HEARTBEAT_BODY_BYTES, parse_heartbeat_body, verify_heartbeat
from fogtrust_crypto.node_auth import declared_length_too_large
from nodes.models import Node
from nodes.node_auth import lookup_node
from nodes.replay_store import DatabaseReplayStore

from .models import Heartbeat
from .policy import current_policy
from .serializers import HeartbeatQuerySerializer, HeartbeatSerializer
from .throttles import IPHeartbeatThrottle, NodeHeartbeatThrottle


def _iso(moment) -> str:
    return moment.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _claimed_fields(raw: bytes) -> dict:
    """counter, load and sent_at from the body, but only if it is a valid heartbeat body."""
    if len(raw) > MAX_HEARTBEAT_BODY_BYTES:
        return {}
    data, code, _ = parse_heartbeat_body(raw)
    if code:
        return {}
    from datetime import datetime

    sent_at = datetime.fromisoformat(data["sent_at"])
    if sent_at.tzinfo is None:
        sent_at = sent_at.replace(tzinfo=timezone.utc)
    return {"counter": data["counter"], "reported_load": data["reported_load"], "sent_at": sent_at}


class NodeHeartbeatView(APIView):
    authentication_classes = []  # signed requests, not sessions: no CSRF (contract section 2.2)
    permission_classes = [AllowAny]
    throttle_classes = [IPHeartbeatThrottle, NodeHeartbeatThrottle]

    def post(self, request):
        if declared_length_too_large(request.META.get("CONTENT_LENGTH"), MAX_HEARTBEAT_BODY_BYTES):
            log_event(
                "heartbeat.rejected", "failure", request=request, actor_type="anonymous",
                reason_code=ErrorCode.PAYLOAD_TOO_LARGE, details={"limit_bytes": MAX_HEARTBEAT_BODY_BYTES},
            )
            raise APIError(ErrorCode.PAYLOAD_TOO_LARGE)

        raw_body = request.body  # the exact bytes the node signed: read BEFORE anything parses them
        window_s, interval_s, policy_version = current_policy()
        result = verify_heartbeat(
            request.headers, request.method, request.get_full_path(), raw_body,
            lookup_node, DatabaseReplayStore(), window_s=window_s,
        )
        now = timezone.now()

        if result.accepted:
            data = result.payload
            Heartbeat.objects.create(
                node_id=result.node_id, counter=data["counter"], nonce=result.nonce,
                sent_at=_claimed_fields(raw_body)["sent_at"], received_at=now,
                reported_load=data["reported_load"], accepted=True,
            )
            Node.objects.filter(pk=result.node_id).update(last_seen_at=now)
            response = Response({"accepted": True, "server_time": _iso(now), "next_heartbeat_in": interval_s})
            response["Cache-Control"] = "no-store"
            return response

        self._record_rejection(request, result, raw_body, policy_version, now)
        raise APIError(result.reason_code)

    @staticmethod
    def _record_rejection(request, result, raw_body, policy_version, now) -> None:
        decision = result.to_decision("heartbeat")
        decision["policy_version"] = policy_version
        record_decision_dict(decision, request=request)
        log_event(
            "heartbeat.rejected", "failure", request=request,
            actor_type="node" if result.node_id else "anonymous", actor_id=result.node_id or "", actor_role="node" if result.node_id else "",
            target_type="node" if result.node_id else "", target_id=result.node_id or "",
            reason_code=result.reason_code, details=result.evidence,
        )
        if result.node_id and Node.objects.filter(pk=result.node_id).exists():
            Heartbeat.objects.create(
                node_id=result.node_id, nonce=result.nonce or "", received_at=now,
                accepted=False, reason_code=result.reason_code, **_claimed_fields(raw_body),
            )


class NodeHeartbeatListView(ListAPIView):
    permission_classes = [require("nodes.view")]
    serializer_class = HeartbeatSerializer
    pagination_class = StandardPagination

    def get_queryset(self):
        try:
            node_id = uuid.UUID(self.kwargs["node_id"])
        except ValueError:
            raise APIError(ErrorCode.NOT_FOUND) from None
        if not Node.objects.filter(pk=node_id).exists():
            raise APIError(ErrorCode.NOT_FOUND)
        query = HeartbeatQuerySerializer(data=self.request.query_params)
        query.is_valid(raise_exception=True)
        filters = query.validated_data
        rows = Heartbeat.objects.filter(node_id=node_id)
        if "accepted" in filters:
            rows = rows.filter(accepted=filters["accepted"] == "true")
        if "reason_code" in filters:
            rows = rows.filter(reason_code=filters["reason_code"])
        return rows