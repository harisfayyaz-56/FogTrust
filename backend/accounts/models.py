"""
User model with a server-enforced role.

Created in Week 1 on purpose: Django only lets you swap in a custom user
model before the first migration. Login, sessions and role permissions
are added on top of this in Week 2.
"""

from django.contrib.auth.models import AbstractUser
from django.contrib.auth.models import UserManager as DjangoUserManager
from django.db import models


class Role(models.TextChoices):
    ADMIN = "admin", "Administrator"
    OPERATOR = "operator", "Operator"
    VIEWER = "viewer", "Viewer"


class UserManager(DjangoUserManager):
    def create_superuser(self, username, email=None, password=None, **extra_fields):
        # A Django superuser is always a FogTrust administrator.
        extra_fields.setdefault("role", Role.ADMIN)
        return super().create_superuser(username, email, password, **extra_fields)


class User(AbstractUser):
    Role = Role

    # Least privilege: a new account can only read until an admin promotes it.
    role = models.CharField(max_length=16, choices=Role.choices, default=Role.VIEWER)

    objects = UserManager()

    # Do not ask for an email in createsuperuser: no unnecessary personal data.
    REQUIRED_FIELDS: list[str] = []

    class Meta:
        db_table = "accounts_user"
        ordering = ["username"]

    @property
    def is_admin_role(self) -> bool:
        return self.role == Role.ADMIN

    @property
    def is_operator_role(self) -> bool:
        return self.role == Role.OPERATOR

    def __str__(self) -> str:
        return f"{self.username} ({self.role})"
