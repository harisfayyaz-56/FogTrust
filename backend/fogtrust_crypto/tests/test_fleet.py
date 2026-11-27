"""The fleet and the crasher: profiles behave as documented, against the stub broker."""

import threading
import uuid

import pytest

from fogtrust_crypto import fleet, node_sim
from fogtrust_crypto.keys import generate_x25519_private_key, generate_private_key, public_key_to_b64, save_private_key

from .stub_broker import StubBroker


@pytest.fixture
def broker():
    stub = StubBroker(generate_x25519_private_key())
    yield stub
    stub.close()


def make_node(tmp_path, broker, name):
    key = generate_private_key()
    key_file = tmp_path / f"{name}.key"
    save_private_key(key, key_file)
    node_id = str(uuid.uuid4())
    node_sim.save_state(node_sim.default_state_path(str(key_file)), {"node_id": node_id, "counter": 0})
    broker.enroll(node_id, public_key_to_b64(key.public_key()))
    return key_file


def run(broker, key_file, profile, **kw):
    results = {}
    fleet.run_node(broker.url, key_file, profile, "n1", kw.get("duration", 0.3), 0.02, kw.get("crash_after", 3), results, threading.Event())
    return results["n1"]


def test_honest_profile_is_always_accepted(tmp_path, broker):
    outcomes = run(broker, make_node(tmp_path, broker, "a"), "honest")
    assert len(outcomes) >= 5 and set(outcomes) == {(200, "OK")}


def test_crasher_goes_silent_after_the_set_number(tmp_path, broker):
    outcomes = run(broker, make_node(tmp_path, broker, "b"), "crasher", crash_after=3, duration=2)
    assert outcomes == [(200, "OK")] * 3 + [("silent", "CRASHED")]


def test_replayer_is_accepted_once_then_refused(tmp_path, broker):
    outcomes = run(broker, make_node(tmp_path, broker, "c"), "replayer")
    assert outcomes[0] == (200, "OK") and all(code == "HEARTBEAT_REPLAYED" for _, code in outcomes[1:]) and len(outcomes) > 3


def test_spoofer_is_never_accepted(tmp_path, broker):
    outcomes = run(broker, make_node(tmp_path, broker, "d"), "spoofer")
    assert set(outcomes) == {(401, "NODE_SIGNATURE_INVALID")}


def test_summary_table_counts_outcomes():
    table = fleet.summarise({"x": [(200, "OK"), (200, "OK"), (401, "HEARTBEAT_REPLAYED")]}, {"x": "replayer"})
    assert "| x | replayer | 3 | 200 OK x2, 401 HEARTBEAT_REPLAYED x1 |" in table


def test_cli_crasher_stops_after_crash_after(tmp_path, broker, capsys):
    key_file = make_node(tmp_path, broker, "e")
    code = node_sim.main(["heartbeat", "--key-file", str(key_file), "--server", broker.url, "--behaviour", "crasher",
                          "--crash-after", "2", "--count", "5", "--interval", "0"])
    out = capsys.readouterr().out
    assert code == 0 and out.count("HTTP 200 OK") == 2 and "node crashed" in out