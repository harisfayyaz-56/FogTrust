from django.db import IntegrityError
from rest_framework import status
from rest_framework.exceptions import APIException
from rest_framework.generics import ListAPIView, RetrieveAPIView
from rest_framework.response import Response
from rest_framework.views import APIView

from accounts.permissions import require
from audit.services import log_event
from core.errors import APIError, ErrorCode
from core.models import Decision
from nodes.authentication import IsEnrolledNode, NodeRequestThrottle, NodeSignatureAuthentication
from tasks.models import Task
from tasks.serializers import TaskDetailSerializer, TaskSubmitSerializer
from tasks.services import assign_next_task


class DuplicateSubmissionError(APIError):
    def __init__(self):
        super().__init__(ErrorCode.DUPLICATE_SUBMISSION)


class TaskSubmitView(APIView):
    permission_classes = [require("tasks.submit")]

    def post(self, request):
        idempotency_key = request.headers.get("Idempotency-Key", "").strip()
        if not idempotency_key:
            return Response(
                {
                    "error": {
                        "code": ErrorCode.VALIDATION_ERROR,
                        "message": "Idempotency-Key header is required.",
                        "request_id": getattr(request, "request_id", ""),
                    }
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        existing = Task.objects.filter(idempotency_key=idempotency_key).first()
        if existing:
            raise DuplicateSubmissionError()

        serializer = TaskSubmitSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        try:
            task = serializer.save(
                created_by=request.user,
                idempotency_key=idempotency_key,
                status=Task.Status.QUEUED,
            )
        except IntegrityError:
            raise DuplicateSubmissionError()

        log_event(
            action="task.submit",
            outcome="success",
            request=request,
            target_type="task",
            target_id=str(task.id),
            details={"task_type": task.task_type, "priority": task.priority},
        )

        # Trigger scheduler
        assign_next_task(task)

        task.refresh_from_db()
        return Response(TaskDetailSerializer(task).data, status=status.HTTP_201_CREATED)


class TaskListView(ListAPIView):
    permission_classes = [require("tasks.view")]
    serializer_class = TaskDetailSerializer

    def get_queryset(self):
        qs = Task.objects.all().select_related("assigned_node")
        task_status = self.request.query_params.get("status")
        node_id = self.request.query_params.get("node")
        if task_status:
            qs = qs.filter(status=task_status)
        if node_id:
            qs = qs.filter(assigned_node_id=node_id)
        return qs


class TaskDetailView(RetrieveAPIView):
    permission_classes = [require("tasks.view")]
    serializer_class = TaskDetailSerializer
    queryset = Task.objects.all().select_related("assigned_node")
    lookup_field = "id"

    def retrieve(self, request, *args, **kwargs):
        instance = self.get_object()
        data = TaskDetailSerializer(instance).data

        # Attach latest assignment decision if present
        latest_decision = Decision.objects.filter(
            subject_type="task",
            subject_id=str(instance.id),
            decision=Decision.DecisionOutcome.ASSIGN,
        ).first()

        if latest_decision:
            data["assignment_decision"] = {
                "decision_id": str(latest_decision.decision_id),
                "decided_at": latest_decision.decided_at,
                "reason": latest_decision.explanation,
                "evidence": latest_decision.evidence,
                "rules_fired": latest_decision.rules_fired,
            }

        return Response(data)


class TaskCancelView(APIView):
    permission_classes = [require("tasks.cancel")]

    def post(self, request, id):
        task = Task.objects.filter(id=id).first()
        if not task:
            return Response(
                {"error": {"code": ErrorCode.TASK_NOT_FOUND, "message": "Task not found."}},
                status=status.HTTP_404_NOT_FOUND,
            )

        if task.status != Task.Status.QUEUED:
            return Response(
                {
                    "error": {
                        "code": ErrorCode.TASK_INVALID_STATE,
                        "message": f"Cannot cancel task in '{task.status}' state. Only queued tasks can be cancelled.",
                    }
                },
                status=status.HTTP_409_CONFLICT,
            )

        task.status = Task.Status.CANCELLED
        task.save(update_fields=["status"])

        log_event(
            action="task.cancel",
            outcome="success",
            request=request,
            target_type="task",
            target_id=str(task.id),
        )

        return Response(TaskDetailSerializer(task).data)


class NodeNextTaskView(APIView):
    """
    Edge nodes poll here for their assigned task.

    The caller is identified by its Ed25519 request signature (X-Node-Id, X-Node-Timestamp,
    X-Node-Nonce, X-Node-Signature), never by the bare node id: the id is not a secret.
    A node can only ever read its own task. See nodes/authentication.py.
    """

    authentication_classes = [NodeSignatureAuthentication]
    permission_classes = [IsEnrolledNode]
    throttle_classes = [NodeRequestThrottle]

    def get(self, request):
        task = Task.objects.filter(
            assigned_node=request.auth,
            status=Task.Status.ASSIGNED,
        ).order_by("priority", "assigned_at").first()

        if not task:
            return Response({"task": None}, status=status.HTTP_200_OK)

        return Response({"task": TaskDetailSerializer(task).data}, status=status.HTTP_200_OK)
