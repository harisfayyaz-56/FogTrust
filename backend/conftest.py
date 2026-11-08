import pytest
from django.core.cache import cache
from rest_framework.test import APIClient

DEFAULT_PASSWORD = "Str0ng-Passw0rd!"


@pytest.fixture(autouse=True)
def _clear_cache():
    """Throttle counters live in the cache; reset them so tests stay independent."""
    cache.clear()
    yield
    cache.clear()


@pytest.fixture
def api_client():
    return APIClient()


@pytest.fixture
def make_user(db, django_user_model):
    def _make(username="user1", password=DEFAULT_PASSWORD, role="viewer", **extra):
        return django_user_model.objects.create_user(username=username, password=password, role=role, **extra)

    return _make


@pytest.fixture
def client_as(make_user):
    """
    A client already signed in through a real session (so session expiry and CSRF apply).
    CSRF checks are off unless you pass enforce_csrf=True.

        client = client_as("admin")
    """

    def _client(role="viewer", username=None, enforce_csrf=False):
        user = make_user(username=username or f"{role}1", role=role)
        client = APIClient(enforce_csrf_checks=enforce_csrf)
        client.force_login(user)
        client.user = user
        return client

    return _client
