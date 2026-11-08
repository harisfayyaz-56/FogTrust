"""
FR-6 node revocation and test T5 (revocation).  Threats ID-4, ID-8, ID-9.

T5: an administrator revokes a node; from that moment the node is refused (NODE_REVOKED,
proved against Member 2's engine in test_node_engine_integration.py), the action is audited
and explained, and nobody else can do it.
"""

import pytest

from audit.services import verify_chain
from core.models import Decision
from nodes.models import Node
from nodes.services import revoke_node
from nodes.signals import node_revoked

from .helpers import audit_events, error_code, last_audit

REASON = "3 integrity failures in 10 minutes"


def url(node):
    return f"/api/v1/nodes/{node.id}/revoke/"


def revoke(client, node, **overrides):
    body = {"reason": REASON, "confirm_name": node.name, **overrides}
    return client.post(url(node), body, format="json")


@pytest.mark.django_db
class TestAdminRevokes:
    def test_revocation_response_and_state(self, client_as, node_factory):
        node, _ = node_factory(name="gateway-03")
        response = revoke(client_as("admin"), node)

        assert response.status_code == 200
        body = response.json()
        assert body["id"] == str(node.id) and body["status"] == "revoked"
        assert body["revoked_by"] == "admin1" and body["revoke_reason"] == REASON and body["revoked_at"]
        node.refresh_from_db()
        assert node.status == "revoked" and node.revoke_source == "manual" and node.revoked_by.username == "admin1"
        assert node.revoked_at is not None

    def test_it_is_audited_with_who_why_and_what(self, client_as, node_factory):
        node, _ = node_factory(name="gateway-03")
        revoke(client_as("admin"), node)

        event = last_audit("node.revoke", "success")
        assert (event.actor_id, event.actor_role) == ("admin1", "admin")
        assert event.target_id == str(node.id)
        assert event.details == {"node_name": "gateway-03", "reason": REASON, "source": "manual"}
        assert event.request_id

    def test_it_is_explained_in_the_evidence_view(self, client_as, node_factory):
        node, _ = node_factory()
        revoke(client_as("admin"), node)

        decision = Decision.objects.get(subject_type="node", decision="revoke")
        assert decision.subject_id == str(node.id)
        assert decision.evidence["reason"] == REASON and decision.evidence["source"] == "manual"
        assert [r["rule"] for r in decision.rules_fired] == ["node_was_active", "authorised_revocation"]

    def test_the_audit_chain_still_verifies(self, client_as, node_factory):
        node, _ = node_factory()
        revoke(client_as("admin"), node)
        assert verify_chain().valid

    def test_node_detail_shows_the_revocation(self, client_as, node_factory):
        node, _ = node_factory(name="gateway-03")
        admin = client_as("admin")
        revoke(admin, node)

        body = admin.get(f"/api/v1/nodes/{node.id}/").json()
        assert body["status"] == "revoked" and body["revoke_reason"] == REASON and body["revoked_by"] == "admin1"

    def test_revoking_one_node_leaves_the_others_alone(self, client_as, node_factory):
        first, _ = node_factory(name="node-one")
        second, _ = node_factory(name="node-two")
        revoke(client_as("admin"), first)

        assert Node.objects.get(pk=second.pk).status == "active"


@pytest.mark.django_db
class TestConfirmationAndValidation:
    def test_wrong_confirmation_does_nothing(self, client_as, node_factory):
        node, _ = node_factory(name="gateway-03")
        response = revoke(client_as("admin"), node, confirm_name="gateway-04")

        assert response.status_code == 400 and error_code(response) == "CONFIRMATION_REQUIRED"
        assert Node.objects.get(pk=node.pk).status == "active"
        assert last_audit("node.revoke", "failure").reason_code == "CONFIRMATION_REQUIRED"
        assert not audit_events("node.revoke", "success")

    @pytest.mark.parametrize("confirm", [None, "", "GATEWAY-03", " gateway-03"])
    def test_missing_or_inexact_confirmation(self, client_as, node_factory, confirm):
        node, _ = node_factory(name="gateway-03")
        body = {"reason": REASON}
        if confirm is not None:
            body["confirm_name"] = confirm
        response = client_as("admin").post(url(node), body, format="json")

        assert response.status_code == 400 and error_code(response) == "CONFIRMATION_REQUIRED"
        assert Node.objects.get(pk=node.pk).status == "active"

    @pytest.mark.parametrize("reason", ["", "too short", "x" * 501, "line\nbreak in the reason", None, 123])
    def test_reason_rules(self, client_as, node_factory, reason):
        node, _ = node_factory()
        response = revoke(client_as("admin"), node, reason=reason)

        assert response.status_code == 400 and error_code(response) == "VALIDATION_ERROR"
        assert Node.objects.get(pk=node.pk).status == "active"

    def test_missing_reason_and_unknown_fields(self, client_as, node_factory):
        node, _ = node_factory()
        admin = client_as("admin")
        assert error_code(admin.post(url(node), {"confirm_name": node.name}, format="json")) == "VALIDATION_ERROR"
        assert error_code(revoke(admin, node, force=True)) == "VALIDATION_ERROR"
        assert Node.objects.get(pk=node.pk).status == "active"

    def test_already_revoked_conflicts(self, client_as, node_factory):
        node, _ = node_factory()
        admin = client_as("admin")
        assert revoke(admin, node).status_code == 200
        response = revoke(admin, node)

        assert response.status_code == 409 and error_code(response) == "NODE_ALREADY_REVOKED"
        assert last_audit("node.revoke", "failure").reason_code == "NODE_ALREADY_REVOKED"
        assert len(audit_events("node.revoke", "success")) == 1
        assert Decision.objects.filter(decision="revoke").count() == 1

    def test_unknown_and_malformed_ids_are_404(self, client_as):
        admin = client_as("admin")
        body = {"reason": REASON, "confirm_name": "gateway-03"}
        assert admin.post("/api/v1/nodes/3f2b8c1e-0000-4000-8000-000000000000/revoke/", body, format="json").status_code == 404
        assert admin.post("/api/v1/nodes/not-a-uuid/revoke/", body, format="json").status_code == 404
        assert admin.post("/api/v1/nodes/1%27%20OR%20%271/revoke/", body, format="json").status_code == 404


@pytest.mark.django_db
class TestOnlyAdministratorsMayRevoke:
    @pytest.mark.parametrize("role", ["operator", "viewer"])
    def test_other_roles_get_a_generic_denial_and_nothing_changes(self, client_as, node_factory, role):
        node, _ = node_factory(name="gateway-03")
        response = revoke(client_as(role), node)

        assert response.status_code == 403 and error_code(response) == "PERMISSION_DENIED"
        assert response.json()["error"]["message"] == "Access denied."
        assert "gateway-03" not in response.content.decode()  # the protected record is not exposed
        assert Node.objects.get(pk=node.pk).status == "active"
        denial = last_audit("access.denied")
        assert denial.actor_role == role and denial.outcome == "denied"
        assert not audit_events("node.revoke", "success")

    def test_anonymous_gets_401(self, api_client, node_factory):
        node, _ = node_factory()
        assert revoke(api_client, node).status_code == 401
        assert Node.objects.get(pk=node.pk).status == "active"

    def test_csrf_is_required(self, client_as, node_factory):
        node, _ = node_factory()
        response = revoke(client_as("admin", enforce_csrf=True), node)

        assert response.status_code == 403 and error_code(response) == "CSRF_FAILED"
        assert Node.objects.get(pk=node.pk).status == "active"

    def test_a_disabled_admin_cannot_revoke(self, client_as, node_factory):
        node, _ = node_factory()
        admin = client_as("admin")
        admin.user.is_active = False
        admin.user.save()

        assert revoke(admin, node).status_code in (401, 403)
        assert Node.objects.get(pk=node.pk).status == "active"

    def test_a_demoted_admin_loses_the_power_immediately(self, client_as, node_factory):
        node, _ = node_factory()
        admin = client_as("admin")
        admin.user.role = "viewer"
        admin.user.save()  # same session, new role: the server reads the role on every request

        assert revoke(admin, node).status_code == 403


@pytest.mark.django_db
class TestAutomaticRevocationAndSignal:
    def test_the_trust_engine_can_revoke_through_the_same_service(self, node_factory):
        node, _ = node_factory()
        revoked = revoke_node(node, reason="trust score 12 below limit 30", by=None, source="automatic")

        assert revoked.status == "revoked" and revoked.revoke_source == "automatic" and revoked.revoked_by is None
        event = last_audit("node.revoke", "success")
        assert (event.actor_type, event.actor_id) == ("system", "trust-engine")
        decision = Decision.objects.get(decision="revoke")
        assert "automatically" in decision.explanation

    def test_the_scheduler_hook_fires_once_after_commit(self, client_as, node_factory, django_capture_on_commit_callbacks):
        node, _ = node_factory(name="gateway-03")
        seen = []

        def receiver(sender, node, source, reason, **kwargs):
            seen.append((node.name, source, reason))

        node_revoked.connect(receiver, weak=False)
        try:
            with django_capture_on_commit_callbacks(execute=True):
                revoke(client_as("admin"), node)
            assert seen == [("gateway-03", "manual", REASON)]
        finally:
            node_revoked.disconnect(receiver)

    def test_a_failing_receiver_cannot_undo_the_revocation(self, client_as, node_factory, django_capture_on_commit_callbacks):
        node, _ = node_factory()

        def broken(sender, **kwargs):
            raise RuntimeError("scheduler bug")

        node_revoked.connect(broken, weak=False)
        try:
            with django_capture_on_commit_callbacks(execute=True):
                response = revoke(client_as("admin"), node)
            assert response.status_code == 200
            assert Node.objects.get(pk=node.pk).status == "revoked"
        finally:
            node_revoked.disconnect(broken)

    def test_no_signal_when_the_revocation_is_refused(self, client_as, node_factory, django_capture_on_commit_callbacks):
        node, _ = node_factory(name="gateway-03")
        seen = []
        receiver = lambda sender, **kwargs: seen.append(1)  # noqa: E731
        node_revoked.connect(receiver, weak=False)
        try:
            with django_capture_on_commit_callbacks(execute=True):
                revoke(client_as("admin"), node, confirm_name="wrong-name")
            assert seen == []
        finally:
            node_revoked.disconnect(receiver)

    def test_the_database_refuses_an_inconsistent_revocation(self, node_factory):
        from django.db import IntegrityError, transaction

        node, _ = node_factory()
        with pytest.raises(IntegrityError), transaction.atomic():
            Node.objects.filter(pk=node.pk).update(status="revoked")  # no revoked_at, no reason
