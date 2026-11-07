"""
User management, administrators only (docs/api-contract.md, section 5.3).

    GET   /api/v1/users/        list (?role=)
    POST  /api/v1/users/        create
    PATCH /api/v1/users/{id}/   change role or enable/disable

An administrator cannot remove their own admin role or disable themselves, so the system can
never be left without a working administrator. Every change is audited (user.create,
user.role_change, user.disable, user.enable) in the same transaction as the change.
"""

from django.db import transaction
from rest_framework import status
from rest_framework.generics import ListAPIView
from rest_framework.response import Response
from rest_framework.views import APIView

from audit.services import log_event
from core.errors import APIError, ErrorCode

from .models import Role, User
from .permissions import require
from .user_serializers import UserCreateSerializer, UserQuerySerializer, UserSerializer, UserUpdateSerializer

SELF_LOCKOUT_MESSAGE = "You cannot remove your own administrator role or disable your own account."


class UserListCreateView(ListAPIView):
    permission_classes = [require("users.manage")]
    serializer_class = UserSerializer

    def get_queryset(self):
        query = UserQuerySerializer(data=self.request.query_params)
        query.is_valid(raise_exception=True)
        queryset = User.objects.order_by("username")
        if "role" in query.validated_data:
            queryset = queryset.filter(role=query.validated_data["role"])
        return queryset

    def post(self, request):
        serializer = UserCreateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data
        with transaction.atomic():
            user = User.objects.create_user(username=data["username"], password=data["password"], role=data["role"])
            log_event(
                "user.create",
                "success",
                request=request,
                target_type="user",
                target_id=user.username,
                details={"role": user.role},  # never the password
            )
        return Response(UserSerializer(user).data, status=status.HTTP_201_CREATED)


class UserDetailView(APIView):
    permission_classes = [require("users.manage")]

    def patch(self, request, user_id):
        user = User.objects.filter(pk=user_id).first() if user_id.isdigit() else None
        if user is None:
            raise APIError(ErrorCode.NOT_FOUND)
        serializer = UserUpdateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        changes = serializer.validated_data

        if user.pk == request.user.pk:
            losing_admin = "role" in changes and changes["role"] != Role.ADMIN
            disabling = changes.get("is_active") is False
            if losing_admin or disabling:
                log_event(
                    "user.role_change" if losing_admin else "user.disable",
                    "failure",
                    request=request,
                    target_type="user",
                    target_id=user.username,
                    reason_code=ErrorCode.CONFLICT,
                    details={"attempted": {k: v for k, v in changes.items()}},
                )
                raise APIError(ErrorCode.CONFLICT, message=SELF_LOCKOUT_MESSAGE)

        with transaction.atomic():
            if "role" in changes and changes["role"] != user.role:
                old_role = user.role
                user.role = changes["role"]
                log_event(
                    "user.role_change",
                    "success",
                    request=request,
                    target_type="user",
                    target_id=user.username,
                    details={"from": old_role, "to": user.role},
                )
            if "is_active" in changes and changes["is_active"] != user.is_active:
                user.is_active = changes["is_active"]
                log_event(
                    "user.enable" if user.is_active else "user.disable",
                    "success",
                    request=request,
                    target_type="user",
                    target_id=user.username,
                )
            user.save(update_fields=["role", "is_active"])
        return Response(UserSerializer(user).data)
