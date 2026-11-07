"""Enrollment-token endpoints (admin only): create, list, cancel. Threat ID-5, ID-10."""

from datetime import timedelta

import pytest
from django.utils import timezone

from nodes.models import EnrollmentToken
from nodes.services import hash_token

from .helpers import audit_events, error_code, last_audit

URL = "/api/v1/enrollment-tokens/"


@pytest.mark.django_db
class TestCreate:
    def test_admin_creates_a_token_and_sees_the_raw_value_once(self, client_as):
        response = client_as("admin").post(URL, {"label": "gateway in lab 2", "expires_in_minutes": 15}, format="json")

        assert response.status_code == 201
        body = response.json()
        assert set(body) == {"id", "label", "token", "expires_at"}
        assert 40 <= len(body["token"]) <= 128
        assert response["Cache-Control"] == "no-store"

    def test_only_the_hash_is_stored(self, client_as):
        raw = client_as("admin").post(URL, {"label": "x"}, format="json").json()["token"]
        row = EnrollmentToken.objects.get()

        assert row.token_hash == hash_token(raw)
        assert raw not in {row.token_hash, row.label}
        assert len(row.token_hash) == 64

    def test_default_expiry_is_fifteen_minutes(self, client_as):
        response = client_as("admin").post(URL, {"label": "x"}, format="json")
        row = EnrollmentToken.objects.get(pk=response.json()["id"])

        assert 14 * 60 < (row.expires_at - row.created_at).total_seconds() <= 15 * 60

    def test_tokens_are_unique(self, client_as):
        client = client_as("admin")
        tokens = {client.post(URL, {"label": f"t{i}"}, format="json").json()["token"] for i in range(5)}
        assert len(tokens) == 5

    def test_creation_is_audited_without_the_token_value(self, client_as):
        client = client_as("admin")
        raw = client.post(URL, {"label": "gateway in lab 2"}, format="json").json()["token"]

        event = last_audit("enroll.token_create", "success")
        assert event.actor_id == "admin1" and event.actor_role == "admin"
        assert event.details["token_label"] == "gateway in lab 2"
        assert raw not in str(event.details) and raw not in event.target_id

    @pytest.mark.parametrize("role", ["operator", "viewer"])
    def test_other_roles_are_denied_and_the_attempt_is_audited(self, client_as, role):
        response = client_as(role).post(URL, {"label": "x"}, format="json")

        assert response.status_code == 403 and error_code(response) == "PERMISSION_DENIED"
        assert EnrollmentToken.objects.count() == 0
        assert last_audit("access.denied").actor_role == role

    def test_anonymous_gets_401(self, api_client):
        assert api_client.post(URL, {"label": "x"}, format="json").status_code == 401

    def test_csrf_is_required(self, client_as):
        client = client_as("admin", enforce_csrf=True)
        response = client.post(URL, {"label": "x"}, format="json")

        assert response.status_code == 403 and error_code(response) == "CSRF_FAILED"
        assert EnrollmentToken.objects.count() == 0

    @pytest.mark.parametrize(
        "body",
        [
            {},
            {"label": ""},
            {"label": "x" * 65},
            {"label": "bad\nlabel"},
            {"label": "ok", "expires_in_minutes": 0},
            {"label": "ok", "expires_in_minutes": 24 * 60 + 1},
            {"label": "ok", "expires_in_minutes": "soon"},
            {"label": "ok", "unexpected": 1},
            {"label": ["list"]},
        ],
    )
    def test_invalid_bodies_are_rejected(self, client_as, body):
        response = client_as("admin").post(URL, body, format="json")

        assert response.status_code == 400 and error_code(response) == "VALIDATION_ERROR"
        assert EnrollmentToken.objects.count() == 0


@pytest.mark.django_db
class TestList:
    def test_list_never_contains_token_values(self, client_as, token_factory):
        _, raw = token_factory(label="lab")
        response = client_as("admin").get(URL)

        assert response.status_code == 200
        text = response.content.decode()
        assert raw not in text and "token_hash" not in text and "token\"" not in text
        row = response.json()["results"][0]
        assert row["status"] == "pending" and row["label"] == "lab" and row["created_by"] is None

    def test_states_and_filter(self, client_as, token_factory):
        client = client_as("admin")
        pending, _ = token_factory(label="pending")
        expired, _ = token_factory(label="expired")
        EnrollmentToken.objects.filter(pk=expired.pk).update(expires_at=timezone.now() - timedelta(seconds=1))
        cancelled, _ = token_factory(label="cancelled")
        EnrollmentToken.objects.filter(pk=cancelled.pk).update(cancelled_at=timezone.now())

        states = {row["label"]: row["status"] for row in client.get(URL).json()["results"]}
        assert states == {"pending": "pending", "expired": "expired", "cancelled": "cancelled"}
        only = client.get(URL, {"status": "expired"}).json()["results"]
        assert [row["label"] for row in only] == ["expired"]

    def test_invalid_filter_is_rejected(self, client_as):
        client = client_as("admin")
        assert error_code(client.get(URL, {"status": "bogus"})) == "VALIDATION_ERROR"
        assert error_code(client.get(URL, {"nope": "1"})) == "VALIDATION_ERROR"

    @pytest.mark.parametrize("role", ["operator", "viewer"])
    def test_other_roles_cannot_list(self, client_as, role):
        assert client_as(role).get(URL).status_code == 403


@pytest.mark.django_db
class TestCancel:
    def test_admin_cancels_an_unused_token(self, client_as, token_factory):
        token, _ = token_factory()
        response = client_as("admin").post(f"{URL}{token.id}/cancel/")

        assert response.status_code == 200 and response.json()["status"] == "cancelled"
        assert last_audit("enroll.token_cancel", "success").target_id == str(token.id)

    def test_cancelling_twice_conflicts(self, client_as, token_factory):
        token, _ = token_factory()
        client = client_as("admin")
        client.post(f"{URL}{token.id}/cancel/")
        response = client.post(f"{URL}{token.id}/cancel/")

        assert response.status_code == 409 and error_code(response) == "CONFLICT"
        assert last_audit("enroll.token_cancel", "failure").reason_code == "CONFLICT"

    def test_unknown_or_malformed_id_is_404(self, client_as):
        client = client_as("admin")
        assert client.post(f"{URL}3f2b8c1e-0000-4000-8000-000000000000/cancel/").status_code == 404
        assert client.post(f"{URL}not-a-uuid/cancel/").status_code == 404

    @pytest.mark.parametrize("role", ["operator", "viewer"])
    def test_other_roles_cannot_cancel(self, client_as, token_factory, role):
        token, _ = token_factory()
        assert client_as(role).post(f"{URL}{token.id}/cancel/").status_code == 403
        token.refresh_from_db()
        assert token.cancelled_at is None
        assert len(audit_events("enroll.token_cancel")) == 0
