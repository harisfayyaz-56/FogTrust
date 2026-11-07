"""Request and response shapes for user management (docs/api-contract.md, section 5.3)."""

from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError as DjangoValidationError
from rest_framework import serializers

from core.serializers import StrictSerializer

from .models import Role, User

USERNAME_PATTERN = r"^[a-zA-Z0-9_.-]{3,150}$"


class UserSerializer(serializers.ModelSerializer):
    """What the API returns about a user. Never the password hash."""

    class Meta:
        model = User
        fields = ["id", "username", "role", "is_active", "last_login", "date_joined"]
        read_only_fields = fields


class UserCreateSerializer(StrictSerializer):
    username = serializers.RegexField(USERNAME_PATTERN)
    # Capped before hashing so a huge "password" cannot be used to burn CPU in Argon2.
    password = serializers.CharField(max_length=128, trim_whitespace=False, write_only=True)
    role = serializers.ChoiceField(choices=Role.choices, required=False, default=Role.VIEWER)  # least privilege

    def validate_username(self, value):
        if User.objects.filter(username__iexact=value).exists():
            raise serializers.ValidationError("A user with this username already exists.")
        return value

    def validate(self, attrs):
        try:
            validate_password(attrs["password"], user=User(username=attrs["username"]))
        except DjangoValidationError as exc:
            raise serializers.ValidationError({"password": list(exc.messages)}) from None
        return attrs


class UserUpdateSerializer(StrictSerializer):
    role = serializers.ChoiceField(choices=Role.choices, required=False)
    is_active = serializers.BooleanField(required=False)

    def validate(self, attrs):
        if not attrs:
            raise serializers.ValidationError("Provide role and/or is_active.")
        return attrs


class UserQuerySerializer(StrictSerializer):
    role = serializers.ChoiceField(choices=Role.choices, required=False)
    page = serializers.IntegerField(min_value=1, required=False)
    page_size = serializers.IntegerField(min_value=1, max_value=100, required=False)
