import pytest
from django.core.cache import cache
from rest_framework.test import APIClient


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
    def _make(username="user1", password="Str0ng-Passw0rd!", role="viewer", **extra):
        return django_user_model.objects.create_user(username=username, password=password, role=role, **extra)

    return _make
