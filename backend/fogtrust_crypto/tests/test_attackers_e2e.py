"""
Week 3 end to end: every simulator attacker against a real local HTTP broker.
Each row is a demo case for T1, T2 or T4: the attacker, the expected HTTP status, and the exact reason code.
"""

import uuid

import pytest

from fogtrust_crypto import codes, node_sim
from fogtrust_crypto.keys import (
    generate_private_key,
    generate_x25519_private_key,
    public_key_to_b64,
    save_private_key,
    x25519_public_to_b64,
)

from .stub_broker import StubBroker


@pytest.fixture
def server_key():
    return generate_x25519_private_key()


@pytest.fixture
def broker(server_key):
    stub = StubBroker(server_key)
    yield stub
    stub.close()


@pytest.fixture
def enrolled(tmp_path, broker):
    key = generate_private_key()
    key_file = tmp_path / "keys" / "gateway-03.key"
    save_private_key(key, key_file)
    node_id = str(uuid.uuid4())
    node_sim.save_state(node_sim.default_state_path(str(key_file)), {"node_id": node_id, "counter": 0})
    broker.enroll(node_id, public_key_to_b64(key.public_key()))
    return str(key_file), node_id


def beat(broker, key_file, behaviour):
    status, payload = node_sim.send_heartbeat(broker.url, key_file, behaviour=behaviour)
    return status, payload.get("error", {}).get("code", "OK")


# ------------------------------------------------------------ heartbeats


def test_honest(broker, enrolled):
    assert beat(broker, enrolled[0], "honest") == (200, "OK")


def test_T1_spoofer_is_rejected(broker, enrolled):
    assert beat(broker, enrolled[0], "spoofer") == (401, codes.NODE_SIGNATURE_INVALID)
    assert broker.store.nonce_count() == 0  # an unauthenticated attacker changed nothing


def test_tamperer_is_rejected(broker, enrolled):
    assert beat(broker, enrolled[0], "tamperer") == (401, codes.NODE_SIGNATURE_INVALID)


def test_T2_replayer_is_accepted_once_then_rejected(broker, enrolled):
    key_file, _ = enrolled
    assert beat(broker, key_file, "replayer") == (200, "OK")  # the original, captured
    assert beat(broker, key_file, "replayer") == (409, codes.HEARTBEAT_REPLAYED)
    assert beat(broker, key_file, "replayer") == (409, codes.HEARTBEAT_REPLAYED)


def test_T2_replay_reason_is_visible_in_the_stored_decision(broker, enrolled):
    key_file, node_id = enrolled
    beat(broker, key_file, "replayer")
    beat(broker, key_file, "replayer")
    denial = broker.decisions[-1].to_decision("heartbeat")
    assert denial["reason_code"] == codes.HEARTBEAT_REPLAYED and denial["subject_id"] == node_id
    assert denial["rules_fired"][-1]["rule"] == "nonce_unique"


def test_drifting_clock_is_rejected_as_stale(broker, enrolled):
    assert beat(broker, enrolled[0], "drifting") == (401, codes.HEARTBEAT_STALE)


def test_regressor_is_accepted_once_then_rejected(broker, enrolled):
    key_file, _ = enrolled
    assert beat(broker, key_file, "regressor") == (200, "OK")
    assert beat(broker, key_file, "regressor") == (409, codes.HEARTBEAT_COUNTER_REGRESSED)


def test_honest_heartbeats_keep_working_after_attacks(broker, enrolled):
    key_file, _ = enrolled
    for behaviour in ("spoofer", "tamperer", "drifting"):
        beat(broker, key_file, behaviour)
    assert beat(broker, key_file, "honest") == (200, "OK")


def test_revoked_node_is_rejected_for_every_behaviour(broker, enrolled):
    key_file, node_id = enrolled
    broker.enroll(node_id, broker.nodes[node_id].public_key, status="revoked")
    assert beat(broker, key_file, "honest") == (403, codes.NODE_REVOKED)


# --------------------------------------------------------------- results


@pytest.fixture
def task(broker, enrolled):
    task_id = str(uuid.uuid4())
    broker.assignments[task_id] = enrolled[1]
    return task_id


def send(broker, enrolled, server_key, task_id, behaviour, payload=b'{"answer":42}'):
    status, body = node_sim.send_result(
        broker.url, enrolled[0], task_id, payload, x25519_public_to_b64(server_key.public_key()), behaviour=behaviour
    )
    return status, body.get("error", {}).get("code", "OK")


def test_honest_result_is_decrypted_by_the_broker(broker, enrolled, server_key, task):
    assert send(broker, enrolled, server_key, task, "honest") == (200, "OK")
    assert broker.plaintexts[task] == b'{"answer":42}'


def test_T4_altered_ciphertext_is_rejected_with_the_integrity_reason(broker, enrolled, server_key, task):
    assert send(broker, enrolled, server_key, task, "tamper_ciphertext") == (422, codes.RESULT_INTEGRITY_FAILED)
    assert task not in broker.plaintexts


def test_T4_ciphertext_altered_in_transit_fails_the_signature(broker, enrolled, server_key, task):
    assert send(broker, enrolled, server_key, task, "tamper_in_transit") == (401, codes.NODE_SIGNATURE_INVALID)


def test_replayed_result_is_rejected(broker, enrolled, server_key, task):
    assert send(broker, enrolled, server_key, task, "replay") == (200, "OK")
    assert send(broker, enrolled, server_key, task, "replay") == (409, codes.HEARTBEAT_REPLAYED)


def test_result_for_a_task_assigned_elsewhere_is_rejected(broker, enrolled, server_key):
    other_task = str(uuid.uuid4())
    broker.assignments[other_task] = str(uuid.uuid4())
    assert send(broker, enrolled, server_key, other_task, "honest") == (403, codes.RESULT_NOT_ASSIGNED)


def test_result_dry_run_sends_nothing(broker, enrolled, server_key, task):
    status, request = node_sim.send_result(
        broker.url, enrolled[0], task, b"{}", x25519_public_to_b64(server_key.public_key()), dry_run=True
    )
    assert status is None and broker.decisions == []
    assert request["path"].endswith(f"/tasks/{task}/result/")


def test_cli_server_keygen_and_result_dry_run(tmp_path, enrolled, server_key, task, capsys):
    server_file = tmp_path / "keys" / "server.key"
    assert node_sim.main(["server-keygen", "--key-file", str(server_file)]) == 0
    public = capsys.readouterr().out.split("server_public_key: ")[1].split()[0]
    assert node_sim.main(["result", "--key-file", enrolled[0], "--task-id", task, "--server-public-key", public, "--dry-run"]) == 0
    assert "X-Node-Signature" in capsys.readouterr().out