import pytest
from django.core.exceptions import ValidationError

from accounts.models import Role, User

pytestmark = pytest.mark.django_db


def test_new_user_defaults_to_least_privilege():
    user = User.objects.create_user(username="alice", password="Str0ng-Passw0rd!")
    assert user.role == Role.VIEWER


def test_password_stored_as_argon2_hash_not_plaintext():
    user = User.objects.create_user(username="bob", password="Str0ng-Passw0rd!")

    assert user.password.startswith("argon2")
    assert "Str0ng-Passw0rd!" not in user.password
    assert user.check_password("Str0ng-Passw0rd!")
    assert not user.check_password("wrong-password")


def test_superuser_is_always_admin_role():
    admin = User.objects.create_superuser(username="root", password="Str0ng-Passw0rd!")
    assert admin.role == Role.ADMIN
    assert admin.is_admin_role


def test_invalid_role_is_rejected_by_validation():
    user = User(username="mallory", role="superadmin")
    user.set_password("Str0ng-Passw0rd!")
    with pytest.raises(ValidationError):
        user.full_clean()
