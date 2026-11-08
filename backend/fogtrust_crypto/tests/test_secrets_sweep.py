"""
C5: secrets sweep. Run a whole session (keygen, enrolment proof, heartbeats, results, every attacker)
and search everything a person or a log file could see for the secrets that must never appear.

Searched: every Decision dict, every result repr, every HTTP response, all command-line output,
all log records, and the text of every key-handling error.
NOT searched: the broker's in-memory `plaintexts` (that is where decrypted data is supposed to go).
"""

import base64
import json
import logging
import uuid

import pytest

from fogtrust_crypto import node_sim
from fogtrust_crypto.keys import (
    CryptoKeyError,
    generate_private_key,
    generate_x25519_private_key,
    load_private_key,
    public_key_to_b64,
    save_private_key,
    save_x25519_private_key,
    sign_enrollment_proof,
    x25519_public_to_b64,
)

from .stub_broker import StubBroker

MARKER = "TOP-SECRET-RESULT-MARKER-7f3a"
TOKEN = "enrol-token-" + "k9" * 16


def raw_private_b64(path):
    return path.read_text().strip()


def test_no_secret_appears_anywhere_a_person_or_a_log_could_see_it(tmp_path, monkeypatch, capsys, caplog):
    caplog.set_level(logging.DEBUG)
    server_key = generate_x25519_private_key()
    server_file = tmp_path / "keys" / "server.key"
    save_x25519_private_key(server_key, server_file)
    broker = StubBroker(server_key)
    try:
        # --- an enrolled node, created through the command line
        key_file = tmp_path / "keys" / "gateway-03.key"
        assert node_sim.main(["keygen", "--key-file", str(key_file)]) == 0
        node_key = load_private_key(key_file)
        node_id = str(uuid.uuid4())
        node_sim.save_state(node_sim.default_state_path(str(key_file)), {"node_id": node_id, "counter": 0})
        broker.enroll(node_id, public_key_to_b64(node_key.public_key()))
        task_id = str(uuid.uuid4())
        broker.assignments[task_id] = node_id
        proof = sign_enrollment_proof(node_key, TOKEN, "gateway-03")

        # --- spy on every request the simulator sends
        sent, responses = [], []
        original_post = node_sim.post

        def spy(server, path, body, headers, timeout=5.0):
            status, payload = original_post(server, path, body, headers, timeout)
            sent.append((headers, body))
            responses.append(json.dumps(payload))
            return status, payload

        monkeypatch.setattr(node_sim, "post", spy)

        server_public = x25519_public_to_b64(server_key.public_key())
        for behaviour in node_sim.BEHAVIOURS:
            for _ in range(2):
                node_sim.send_heartbeat(broker.url, str(key_file), behaviour=behaviour)
        for behaviour in node_sim.RESULT_BEHAVIOURS:
            for _ in range(2):
                node_sim.send_result(broker.url, str(key_file), task_id, MARKER.encode(), server_public, behaviour=behaviour)
        node_sim.main(["result", "--key-file", str(key_file), "--task-id", task_id, "--server-public-key", server_public, "--dry-run"])
        node_sim.main(["heartbeat", "--key-file", str(key_file), "--dry-run"])

        # --- the errors key handling can produce
        errors = []
        corrupt = tmp_path / "keys" / "corrupt.key"
        corrupt.write_text(raw_private_b64(key_file)[:-6] + "!!!!!!\n")
        corrupt.chmod(0o600)
        for action in (lambda: load_private_key(corrupt), lambda: save_private_key(node_key, key_file), lambda: load_private_key(tmp_path / "missing.key")):
            with pytest.raises(CryptoKeyError) as caught:
                action()
            errors.append(str(caught.value))

        # --- everything a person or a log could see
        seen = []
        for result in broker.decisions:
            seen += [json.dumps(result.to_decision("heartbeat"), default=str), repr(result)]
        seen += responses + errors + [r.getMessage() for r in caplog.records]
        out = capsys.readouterr()
        seen += [out.out, out.err]
        haystack = "\n".join(seen)

        # --- the secrets
        secrets = {
            "node private key": raw_private_b64(key_file),
            "server private key": raw_private_b64(server_file),
            "enrolment token": TOKEN,
            "result plaintext": MARKER,
        }
        for headers, body in sent:
            secrets[f"signature {headers['X-Node-Signature'][:10]}"] = headers["X-Node-Signature"]
        secrets["enrolment proof"] = proof
        for name, secret in secrets.items():
            assert secret not in haystack, f"{name} leaked"
        # the raw key bytes in hex or base64 of the 32 seed bytes must not appear either
        assert base64.b64decode(raw_private_b64(key_file)).hex() not in haystack
        assert len(haystack) > 2000  # the sweep really looked at something
        assert any(r.accepted for r in broker.decisions) and any(not r.accepted for r in broker.decisions)
    finally:
        broker.close()