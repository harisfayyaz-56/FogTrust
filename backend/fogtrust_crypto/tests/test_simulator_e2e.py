"""
End-to-end for Week 2, without Member 1's endpoint: simulator -> real HTTP -> verifier.
A throwaway local server stands in for the broker and calls verify_node_request exactly
as the Django view will.
"""

import json
import threading
import uuid
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from fogtrust_crypto import codes, node_sim
from fogtrust_crypto.keys import generate_private_key, public_key_to_b64, save_private_key
from fogtrust_crypto.node_auth import NodeInfo, verify_node_request


class StubBroker:
    def __init__(self):
        self.nodes = {}
        self.decisions = []
        broker = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
                result = verify_node_request(dict(self.headers.items()), "POST", self.path, body, broker.nodes.get)
                broker.decisions.append(result)
                if result.accepted:
                    status, payload = 200, {"accepted": True}
                else:
                    status = {codes.NODE_REVOKED: 403}.get(result.reason_code, 401)
                    payload = {"error": {"code": result.reason_code}}
                data = json.dumps(payload).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, *args):
                pass

        self.server = HTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_port}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()


@pytest.fixture
def broker():
    stub = StubBroker()
    yield stub
    stub.close()


@pytest.fixture
def enrolled(tmp_path, broker):
    """An enrolled honest node: key file, state file, and an entry in the broker's node table."""
    key = generate_private_key()
    key_file = tmp_path / "keys" / "gateway-03.key"
    save_private_key(key, key_file)
    node_id = str(uuid.uuid4())
    node_sim.save_state(node_sim.default_state_path(str(key_file)), {"node_id": node_id, "counter": 0})
    broker.nodes[node_id] = NodeInfo(public_key_to_b64(key.public_key()), "active")
    return str(key_file), node_id


def test_honest_node_heartbeat_is_accepted_end_to_end(broker, enrolled):
    key_file, node_id = enrolled
    status, payload = node_sim.send_heartbeat(broker.url, key_file, load=2)
    assert (status, payload) == (200, {"accepted": True})
    assert broker.decisions[-1].node_id == node_id


def test_counter_increases_and_is_persisted(broker, enrolled):
    key_file, _ = enrolled
    for _ in range(3):
        assert node_sim.send_heartbeat(broker.url, key_file)[0] == 200
    state = node_sim.load_state(node_sim.default_state_path(key_file))
    assert state["counter"] == 3


def test_counter_is_persisted_even_if_the_server_is_down(enrolled):
    key_file, _ = enrolled
    with pytest.raises(OSError):
        node_sim.send_heartbeat("http://127.0.0.1:9", key_file)  # nothing listens on port 9
    assert node_sim.load_state(node_sim.default_state_path(key_file))["counter"] == 1


def test_dry_run_sends_nothing_and_does_not_advance_the_counter(broker, enrolled):
    key_file, _ = enrolled
    status, request = node_sim.send_heartbeat(broker.url, key_file, dry_run=True)
    assert status is None and broker.decisions == []
    assert node_sim.load_state(node_sim.default_state_path(key_file))["counter"] == 0
    assert set(request["headers"]) == {"X-Node-Id", "X-Node-Timestamp", "X-Node-Nonce", "X-Node-Signature"}


def test_node_using_the_wrong_key_is_rejected(broker, enrolled, tmp_path):
    key_file, node_id = enrolled
    # same node id, but the broker has registered a different key for it
    broker.nodes[node_id] = NodeInfo(public_key_to_b64(generate_private_key().public_key()), "active")
    status, payload = node_sim.send_heartbeat(broker.url, key_file)
    assert status == 401 and payload["error"]["code"] == codes.NODE_SIGNATURE_INVALID


def test_revoked_node_is_rejected(broker, enrolled):
    key_file, node_id = enrolled
    broker.nodes[node_id] = NodeInfo(broker.nodes[node_id].public_key, "revoked")
    status, payload = node_sim.send_heartbeat(broker.url, key_file)
    assert status == 403 and payload["error"]["code"] == codes.NODE_REVOKED


def test_body_altered_in_transit_is_rejected(broker, enrolled):
    key_file, node_id = enrolled
    body, headers = node_sim.honest_behaviour(
        node_sim.load_private_key(key_file), node_id, counter=1, load=0, now=1_763_547_631.0
    )
    altered = body.replace(b'"counter":1', b'"counter":999')
    status, payload = node_sim.post(broker.url, node_sim.HEARTBEAT_PATH, altered, headers)
    assert status == 401 and payload["error"]["code"] == codes.NODE_SIGNATURE_INVALID


def test_unknown_node_is_rejected(broker, enrolled):
    key_file, node_id = enrolled
    del broker.nodes[node_id]
    status, payload = node_sim.send_heartbeat(broker.url, key_file)
    assert status == 401 and payload["error"]["code"] == codes.NODE_UNKNOWN


def test_heartbeat_body_shape_matches_the_contract(enrolled):
    key_file, _ = enrolled
    _, request = node_sim.send_heartbeat("unused", key_file, load=1, dry_run=True)
    body = json.loads(request["body"])
    assert set(body) == {"counter", "reported_load", "sent_at"}
    assert body["counter"] == 1 and body["reported_load"] == 1 and body["sent_at"].endswith("Z")


def test_cli_keygen_then_dry_run(tmp_path, capsys):
    key_file = tmp_path / "keys" / "cli.key"
    assert node_sim.main(["keygen", "--key-file", str(key_file)]) == 0
    node_sim.save_state(node_sim.default_state_path(str(key_file)), {"node_id": str(uuid.uuid4()), "counter": 0})
    assert node_sim.main(["heartbeat", "--key-file", str(key_file), "--dry-run"]) == 0
    assert "X-Node-Signature" in capsys.readouterr().out


def test_cli_refuses_to_overwrite_an_existing_key(tmp_path):
    key_file = tmp_path / "cli.key"
    assert node_sim.main(["keygen", "--key-file", str(key_file)]) == 0
    assert node_sim.main(["keygen", "--key-file", str(key_file)]) == 2