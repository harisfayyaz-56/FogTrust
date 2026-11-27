"""
T5 + FR-3: a revoked node's in-flight tasks go back to the queue and only reach active nodes.
"""

import pytest

from accounts.models import User
from audit.models import AuditEvent
from audit.services import verify_chain
from nodes.models import Node
from nodes.services import revoke_node
from tasks.models import Task
from tasks.services import assign_next_task
from trust.models import PolicyConfig

pytestmark = pytest.mark.django_db


def make_node(name, **extra):
    fields = {"public_key": name.ljust(44, "k")[:44], "key_fingerprint": name.ljust(64, "f")[:64],
              "capacity": 4, "trust_score": 90, "status": Node.Status.ACTIVE}
    fields.update(extra)
    return Node.objects.create(name=name, **fields)


def make_task(key, node=None, attempts=1, max_attempts=3, status=Task.Status.ASSIGNED):
    user, _ = User.objects.get_or_create(username="operator1", defaults={"role": "operator"})
    return Task.objects.create(
        task_type="checksum", payload={"sample": key}, priority=1, status=status,
        idempotency_key=key, assigned_node=node, attempts=attempts, max_attempts=max_attempts, created_by=user,
    )


@pytest.fixture
def setup(make_user, django_capture_on_commit_callbacks):
    PolicyConfig.objects.create(version=1, values={"trust_threshold": 60, "initial_score": 80}, change_reason="test")
    admin = make_user(username="admin1", role="admin")
    bad = make_node("bad-node", current_load=3)
    good = make_node("good-node")
    tasks = {
        "retry": make_task("retry", bad, attempts=1),
        "last": make_task("last", bad, attempts=3, max_attempts=3),
        "done": make_task("done", bad, status=Task.Status.COMPLETED),
        "other": make_task("other", good),
    }
    with django_capture_on_commit_callbacks(execute=True):
        revoke_node(bad, reason="integrity failures seen", by=admin)
    for task in tasks.values():
        task.refresh_from_db()
    bad.refresh_from_db()
    return bad, good, tasks


def test_in_flight_tasks_return_to_the_queue(setup):
    _, _, tasks = setup
    assert tasks["retry"].status == Task.Status.QUEUED
    assert tasks["retry"].assigned_node is None


def test_a_task_out_of_attempts_fails_with_the_reason(setup):
    _, _, tasks = setup
    assert tasks["last"].status == Task.Status.FAILED
    event = AuditEvent.objects.get(action="task.fail", target_id=str(tasks["last"].id))
    assert (event.reason_code, event.actor_id) == ("NODE_REVOKED", "scheduler")


def test_finished_tasks_and_other_nodes_are_untouched(setup):
    _, good, tasks = setup
    assert tasks["done"].status == Task.Status.COMPLETED
    assert tasks["other"].status == Task.Status.ASSIGNED
    assert tasks["other"].assigned_node == good


def test_load_is_released_and_trust_is_not_charged(setup):
    bad, _, _ = setup
    assert bad.current_load == 0
    assert bad.trust_score == 90


def test_the_requeued_task_goes_to_an_active_node_only(setup):
    bad, good, tasks = setup
    assigned = assign_next_task(tasks["retry"])
    assert assigned.assigned_node == good
    assert assigned.assigned_node != bad


def test_requeue_is_audited_and_the_chain_stays_valid(setup):
    _, _, tasks = setup
    event = AuditEvent.objects.get(action="task.reassign", target_id=str(tasks["retry"].id))
    assert event.details["cause"] == "node_revoked"
    assert event.details["revoked_node_name"] == "bad-node"
    assert verify_chain().valid


def test_automatic_revocation_also_requeues(make_user, django_capture_on_commit_callbacks):
    PolicyConfig.objects.create(version=1, values={"trust_threshold": 60}, change_reason="test")
    node = make_node("auto-node", current_load=1)
    task = make_task("auto", node)
    with django_capture_on_commit_callbacks(execute=True):
        revoke_node(node, reason="trust score below policy limit", source=Node.RevokeSource.AUTOMATIC)
    task.refresh_from_db()
    assert task.status == Task.Status.QUEUED
