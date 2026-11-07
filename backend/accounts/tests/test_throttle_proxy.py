"""
Regression test for a real defect found in Week 3 review.

DRF trusts the client-supplied X-Forwarded-For header unless NUM_PROXIES is set, so a script that
sent a different value with every request was never throttled by IP (threat ID-1). settings.py now
sets NUM_PROXIES=0: only the socket address (REMOTE_ADDR) identifies a client.
"""

import pytest


@pytest.mark.django_db
def test_rotating_x_forwarded_for_cannot_bypass_the_login_limit(api_client):
    statuses = [
        api_client.post(
            "/api/v1/auth/login/", {"username": f"guess{i}", "password": "wrong"}, format="json",
            HTTP_X_FORWARDED_FOR=f"198.51.100.{i}",
        ).status_code
        for i in range(8)
    ]

    assert statuses[:5] == [401] * 5
    assert statuses[5:] == [429] * 3


def test_the_trusted_proxy_count_defaults_to_zero(settings):
    assert settings.REST_FRAMEWORK["NUM_PROXIES"] == 0
