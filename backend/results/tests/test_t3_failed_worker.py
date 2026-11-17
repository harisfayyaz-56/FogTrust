"""
T3, across all slices: a worker crashes, the scheduler notices, the task moves, the other worker finishes it.

  Member 2: signed heartbeats set Node.last_seen_at, rejected or replayed ones must NOT; encrypted result completes the task
  Member 3: assign_next_task, detect_stalled_tasks, trust penalty
  Member 1: nodes, audit
"""

import json
from datetime import timedelta

import pytest
from django.utils import timezone

from nodes.models import Node
from tasks.models import Task
from tasks.services import assign_next_task, detect_stalled_tasks

from .test_result_api import PLAINTEXT, make_task, post, server_key, submission  # noqa: F401
from .test_trust_integration import HEARTBEAT, heartbeat, meta


@pytest.mark.django_db
def test_crashed_worker_is_replaced_and_the_task_still_completes(api_client, node_factory, server_key, make_user):
    admin = make_user(username="creator", role="admin")
    a, key_a = node_factory(name="worker-a")
    b, key_b = node_factory(name="worker-b")
    task = Task.objects.create(task_type="checksum", payload={}, status=Task.Status.QUEUED, idempotency_key="t3-demo", created_by=admin)

    # 1. both workers are alive: signed heartbeats are accepted and recorded
    _, headers_a, body_a = heartbeat(api_client, key_a, a.id, 1)
    assert heartbeat(api_client, key_b, b.id, 1)[0].status_code == 200
    a.refresh_from_db(), b.refresh_from_db()
    assert a.last_seen_at and b.last_seen_at

    # 2. the scheduler assigns the task to one of them
    assigned = assign_next_task(task)
    first = Node.objects.get(pk=assigned.assigned_node_id)
    other_key = key_b if first.pk == a.pk else key_a
    other = b if first.pk == a.pk else a
    first_key = key_a if first.pk == a.pk else key_b
    assert first.current_load == 1 and assigned.attempts == 1

    # 3. the assigned worker crashes: silence for two minutes, while the other keeps sending heartbeats
    Node.objects.filter(pk=first.pk).update(last_seen_at=timezone.now() - timedelta(seconds=120))
    assert heartbeat(api_client, other_key, other.id, 2)[0].status_code == 200

    # 4. an attacker tries to keep the dead worker "alive" by replaying its old heartbeat
    captured_headers, captured_body = (headers_a, body_a) if first.pk == a.pk else (None, None)
    if captured_headers:
        replay = api_client.post(HEARTBEAT, data=captured_body, content_type="application/json", **meta(captured_headers))
        assert replay.json()["error"]["code"] == "HEARTBEAT_REPLAYED"
    first.refresh_from_db()
    assert first.last_seen_at < timezone.now() - timedelta(seconds=100)  # the replay did not refresh it

    # 5. the scheduler detects the stall, requeues the task, frees the slot and penalises the crashed worker
    moved = detect_stalled_tasks(stall_seconds=60)
    assert [t.id for t in moved] == [task.id]
    task.refresh_from_db(), first.refresh_from_db()
    assert task.status == Task.Status.QUEUED and task.assigned_node is None
    assert first.current_load == 0 and first.trust_score == 65  # 80 - 15

    # 6. the task goes to the healthy worker (higher trust, same load)
    again = assign_next_task(task)
    assert again.assigned_node_id == other.pk and again.attempts == 2

    # 7. the healthy worker sends the encrypted result: the task completes, the worker is rewarded and has room again
    assert post(api_client, *submission(other_key, other.id, task.id, server_key[1])).status_code == 201
    task.refresh_from_db(), other.refresh_from_db()
    assert task.status == Task.Status.COMPLETED
    assert other.current_load == 0 and other.trust_score == 85


@pytest.mark.django_db
def test_a_node_that_keeps_heartbeating_is_not_declared_stalled(api_client, node_factory, make_user):
    admin = make_user(username="creator", role="admin")
    node, key = node_factory(name="steady")
    task = Task.objects.create(task_type="checksum", payload={}, status=Task.Status.QUEUED, idempotency_key="steady", created_by=admin)
    assign_next_task(task)
    assert heartbeat(api_client, key, node.id, 1)[0].status_code == 200
    assert detect_stalled_tasks(stall_seconds=60) == []
    task.refresh_from_db()
    assert task.status == Task.Status.ASSIGNED


@pytest.mark.django_db
def test_rejected_heartbeats_do_not_keep_a_silent_worker_alive(api_client, node_factory, make_user):
    from fogtrust_crypto.keys import generate_private_key

    admin = make_user(username="creator", role="admin")
    node, key = node_factory(name="silent")
    task = Task.objects.create(task_type="checksum", payload={}, status=Task.Status.QUEUED, idempotency_key="silent", created_by=admin)
    assign_next_task(task)
    Node.objects.filter(pk=node.pk).update(last_seen_at=timezone.now() - timedelta(seconds=300))
    for counter in range(1, 6):  # a spoofer pretends to be the node
        assert heartbeat(api_client, generate_private_key(), node.id, counter)[0].status_code == 401
    node.refresh_from_db()
    assert node.last_seen_at < timezone.now() - timedelta(seconds=200)
    assert [t.id for t in detect_stalled_tasks(stall_seconds=60)] == [task.id]