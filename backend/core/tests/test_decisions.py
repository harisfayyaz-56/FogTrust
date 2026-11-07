"""The shared Decision record and the evidence view (GET /decisions/). Threats ID-4, ID-10."""

from datetime import timedelta

import pytest
from django.utils import timezone

from core.decisions import record_decision, record_decision_dict
from core.models import Decision

URL = "/api/v1/decisions/"


def make(**overrides):
    values = dict(
        subject_type="heartbeat", subject_id="node-1", decision="deny", reason_code="HEARTBEAT_REPLAYED",
        explanation="Nonce was already used.", rules_fired=[{"rule": "nonce_unique", "passed": False, "detail": "seen"}],
        evidence={"counter": 41}, engine_name="replay_guard", engine_version="1.0.0",
    )
    values.update(overrides)
    return record_decision(**values)


@pytest.mark.django_db
class TestRecording:
    def test_a_decision_keeps_everything_needed_to_reproduce_it(self):
        row = make(thresholds={"timestamp_window_s": 30}, policy_version=3, latency_ms=2.7449, request=None)

        assert row.pk and row.decided_at
        assert row.rules_fired == [{"rule": "nonce_unique", "passed": False, "detail": "seen"}]
        assert row.thresholds == {"timestamp_window_s": 30} and row.policy_version == 3 and row.latency_ms == 2.745

    def test_secrets_in_evidence_are_redacted_at_any_depth(self):
        row = make(evidence={"counter": 1, "private_key": "AAAA", "nested": {"session_token": "x", "ok": 1}, "token_id": "t-1"})

        assert row.evidence == {"counter": 1, "private_key": "[REDACTED]", "nested": {"session_token": "[REDACTED]", "ok": 1}, "token_id": "t-1"}

    def test_long_text_is_truncated(self):
        row = make(explanation="x" * 900, evidence={"note": "y" * 900}, rules_fired=[{"rule": "r" * 200, "passed": 1, "detail": "d" * 900}])

        assert len(row.explanation) == 500 and len(row.evidence["note"]) <= 256
        assert len(row.rules_fired[0]["rule"]) == 64 and len(row.rules_fired[0]["detail"]) == 256

    @pytest.mark.parametrize("field,value", [("subject_type", "bogus"), ("decision", "maybe")])
    def test_enumerations_are_checked(self, field, value):
        with pytest.raises(ValueError):
            make(**{field: value})

    def test_record_decision_dict_accepts_the_engine_shape(self):
        row = record_decision_dict(
            {
                "subject_type": "heartbeat", "subject_id": "n", "decision": "allow", "reason_code": "OK",
                "explanation": "Heartbeat accepted.", "rules_fired": [], "evidence": {"counter": 1},
                "engine_name": "heartbeat_verifier", "engine_version": "0.2.0", "policy_version": None,
                "thresholds": {"timestamp_window_s": 30}, "decided_at": "2026-11-12T09:30:01.204000Z", "latency_ms": 0.14,
            }
        )
        assert row.decided_at.year == 2026 and row.engine_version == "0.2.0"


@pytest.mark.django_db
class TestEvidenceView:
    @pytest.mark.parametrize("role", ["admin", "operator", "viewer"])
    def test_every_role_can_read(self, client_as, role):
        make()
        response = client_as(role).get(URL)

        assert response.status_code == 200
        row = response.json()["results"][0]
        assert set(row) == {
            "decision_id", "subject_type", "subject_id", "decision", "reason_code", "explanation", "rules_fired",
            "evidence", "engine_name", "engine_version", "policy_version", "thresholds", "request_id", "decided_at", "latency_ms",
        }

    def test_anonymous_gets_401(self, api_client):
        assert api_client.get(URL).status_code == 401

    def test_it_is_read_only(self, client_as):
        client = client_as("admin")
        for method in ("post", "put", "patch", "delete"):
            assert getattr(client, method)(URL, {}, format="json").status_code == 405

    def test_newest_first_and_filters(self, client_as):
        now = timezone.now()
        make(subject_type="enrollment", decision="allow", reason_code="OK", decided_at=now - timedelta(hours=3))
        make(subject_type="heartbeat", decision="deny", reason_code="HEARTBEAT_STALE", decided_at=now - timedelta(hours=2))
        make(subject_type="heartbeat", decision="deny", reason_code="HEARTBEAT_REPLAYED", subject_id="node-2", decided_at=now - timedelta(hours=1))
        client = client_as("viewer")

        codes = lambda params: [r["reason_code"] for r in client.get(URL, params).json()["results"]]  # noqa: E731
        assert codes({}) == ["HEARTBEAT_REPLAYED", "HEARTBEAT_STALE", "OK"]
        assert codes({"subject_type": "heartbeat"}) == ["HEARTBEAT_REPLAYED", "HEARTBEAT_STALE"]
        assert codes({"decision": "allow"}) == ["OK"]
        assert codes({"reason_code": "HEARTBEAT_STALE"}) == ["HEARTBEAT_STALE"]
        assert codes({"subject_id": "node-2"}) == ["HEARTBEAT_REPLAYED"]
        assert codes({"since": (now - timedelta(minutes=150)).isoformat()}) == ["HEARTBEAT_REPLAYED", "HEARTBEAT_STALE"]
        assert codes({"until": (now - timedelta(minutes=150)).isoformat()}) == ["OK"]

    @pytest.mark.parametrize(
        "params",
        [{"subject_type": "bogus"}, {"decision": "maybe"}, {"reason_code": "lower"}, {"subject_id": "a b"}, {"since": "yesterday"},
         {"since": "2026-02-01T00:00:00Z", "until": "2026-01-01T00:00:00Z"}, {"page_size": 500}, {"surprise": "1"}],
    )
    def test_invalid_filters_are_rejected_safely(self, client_as, params):
        response = client_as("viewer").get(URL, params)
        assert response.status_code == 400 and response.json()["error"]["code"] == "VALIDATION_ERROR"

    def test_injection_in_filters_is_harmless(self, client_as):
        make()
        client = client_as("viewer")
        for params in ({"reason_code": "X' OR '1'='1"}, {"subject_id": "1;DROP TABLE core_decision"}):
            assert client.get(URL, params).status_code == 400
        assert Decision.objects.count() == 1
