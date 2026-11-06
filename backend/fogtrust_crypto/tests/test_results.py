"""T4: altered result, plus the rest of the encrypted-result checks."""

import base64
import json
import os
import stat
import uuid

import pytest

from fogtrust_crypto import codes
from fogtrust_crypto.keys import (
    CryptoKeyError,
    generate_x25519_private_key,
    load_x25519_private_key,
    save_x25519_private_key,
    x25519_public_from_b64,
    x25519_public_to_b64,
)
from fogtrust_crypto.node_auth import sign_request
from fogtrust_crypto.replay import InMemoryReplayStore
from fogtrust_crypto.results import (
    MAX_CIPHERTEXT_B64,
    MAX_PLAINTEXT_BYTES,
    MAX_RESULT_BODY_BYTES,
    decrypt_envelope,
    encrypt_result,
    verify_result_request,
)

from .helpers import NOW, Node

PLAINTEXT = b'{"answer": 42, "unit": "celsius"}'


@pytest.fixture
def server():
    return generate_x25519_private_key()


@pytest.fixture
def server_pub(server):
    return x25519_public_to_b64(server.public_key())


@pytest.fixture
def node():
    return Node()


@pytest.fixture
def task_id():
    return str(uuid.uuid4())


def flip(b64: str, index: int = 0) -> str:
    raw = bytearray(base64.b64decode(b64))
    raw[index] ^= 0x01
    return base64.b64encode(bytes(raw)).decode()


# ------------------------------------------------------------ encryption


def test_round_trip(server, server_pub, node, task_id):
    envelope = encrypt_result(server_pub, node.id, task_id, PLAINTEXT)
    outcome = decrypt_envelope(server, node.id, task_id, envelope)
    assert outcome.accepted and outcome.plaintext == PLAINTEXT
    assert outcome.result.reason_code == codes.OK


def test_envelope_matches_the_data_model_field_sizes(server_pub, node, task_id):
    envelope = encrypt_result(server_pub, node.id, task_id, PLAINTEXT)
    assert set(envelope) == {"ephemeral_public_key", "nonce", "ciphertext"}
    assert len(envelope["ephemeral_public_key"]) == 44  # char(44)
    assert len(envelope["nonce"]) == 16  # char(16): 12 bytes
    assert len(base64.b64decode(envelope["ciphertext"])) == len(PLAINTEXT) + 16  # data + GCM tag


def test_every_encryption_is_different(server_pub, node, task_id):
    a = encrypt_result(server_pub, node.id, task_id, PLAINTEXT)
    b = encrypt_result(server_pub, node.id, task_id, PLAINTEXT)
    assert a["ciphertext"] != b["ciphertext"] and a["ephemeral_public_key"] != b["ephemeral_public_key"]


def test_ciphertext_does_not_contain_the_plaintext(server_pub, node, task_id):
    envelope = encrypt_result(server_pub, node.id, task_id, PLAINTEXT)
    assert PLAINTEXT not in base64.b64decode(envelope["ciphertext"])


def test_empty_plaintext_round_trips(server, server_pub, node, task_id):
    envelope = encrypt_result(server_pub, node.id, task_id, b"")
    assert decrypt_envelope(server, node.id, task_id, envelope).plaintext == b""


def test_maximum_size_plaintext_round_trips_and_one_more_byte_is_refused(server, server_pub, node, task_id):
    big = os.urandom(MAX_PLAINTEXT_BYTES)
    envelope = encrypt_result(server_pub, node.id, task_id, big)
    assert len(envelope["ciphertext"]) <= MAX_CIPHERTEXT_B64
    assert decrypt_envelope(server, node.id, task_id, envelope).plaintext == big
    with pytest.raises(ValueError):
        encrypt_result(server_pub, node.id, task_id, big + b"x")


# ------------------------------------------------------ T4: altered result


@pytest.mark.parametrize("position", [0, 5, -1])  # first byte, middle, and the tag's last byte
def test_T4_one_flipped_ciphertext_byte_is_detected(server, server_pub, node, task_id, position):
    envelope = encrypt_result(server_pub, node.id, task_id, PLAINTEXT)
    envelope["ciphertext"] = flip(envelope["ciphertext"], position)
    outcome = decrypt_envelope(server, node.id, task_id, envelope)
    assert not outcome.accepted and outcome.result.reason_code == codes.RESULT_INTEGRITY_FAILED
    assert outcome.plaintext is None and outcome.plaintext_sha256 is None
    assert outcome.result.rules_fired[-1]["rule"] == "aes_gcm_tag" and not outcome.result.rules_fired[-1]["passed"]


def test_altered_nonce_is_detected(server, server_pub, node, task_id):
    envelope = encrypt_result(server_pub, node.id, task_id, PLAINTEXT)
    envelope["nonce"] = flip(envelope["nonce"])
    assert decrypt_envelope(server, node.id, task_id, envelope).result.reason_code == codes.RESULT_INTEGRITY_FAILED


def test_swapped_ephemeral_key_is_detected(server, server_pub, node, task_id):
    envelope = encrypt_result(server_pub, node.id, task_id, PLAINTEXT)
    envelope["ephemeral_public_key"] = encrypt_result(server_pub, node.id, task_id, b"x")["ephemeral_public_key"]
    assert decrypt_envelope(server, node.id, task_id, envelope).result.reason_code == codes.RESULT_INTEGRITY_FAILED


def test_ciphertext_moved_to_another_task_is_detected(server, server_pub, node, task_id):
    envelope = encrypt_result(server_pub, node.id, task_id, PLAINTEXT)
    other_task = str(uuid.uuid4())
    assert decrypt_envelope(server, node.id, other_task, envelope).result.reason_code == codes.RESULT_INTEGRITY_FAILED


def test_ciphertext_attributed_to_another_node_is_detected(server, server_pub, node, task_id):
    envelope = encrypt_result(server_pub, node.id, task_id, PLAINTEXT)
    assert decrypt_envelope(server, str(uuid.uuid4()), task_id, envelope).result.reason_code == codes.RESULT_INTEGRITY_FAILED


def test_wrong_server_key_fails_integrity(server_pub, node, task_id):
    envelope = encrypt_result(server_pub, node.id, task_id, PLAINTEXT)
    other = generate_x25519_private_key()
    assert decrypt_envelope(other, node.id, task_id, envelope).result.reason_code == codes.RESULT_INTEGRITY_FAILED


# ------------------------------------------------------ malformed envelopes


@pytest.mark.parametrize(
    "mutate",
    [
        lambda e: {**e, "extra": "x"},
        lambda e: {k: v for k, v in e.items() if k != "nonce"},
        lambda e: [],
        lambda e: "text",
        lambda e: None,
        lambda e: {**e, "nonce": "AAAA"},
        lambda e: {**e, "nonce": 5},
        lambda e: {**e, "ephemeral_public_key": "short"},
        lambda e: {**e, "ephemeral_public_key": base64.b64encode(bytes(32)).decode()},  # all-zero (low-order) key
        lambda e: {**e, "ciphertext": "!!!not base64!!!"},
        lambda e: {**e, "ciphertext": 123},
        lambda e: {**e, "ciphertext": base64.b64encode(b"short").decode()},  # shorter than the tag
    ],
)
def test_malformed_envelopes_fail_safely(server, server_pub, node, task_id, mutate):
    envelope = mutate(encrypt_result(server_pub, node.id, task_id, PLAINTEXT))
    outcome = decrypt_envelope(server, node.id, task_id, envelope)
    assert not outcome.accepted and outcome.result.reason_code == codes.VALIDATION_ERROR


def test_oversized_ciphertext_is_refused_before_decoding(server, server_pub, node, task_id):
    envelope = encrypt_result(server_pub, node.id, task_id, PLAINTEXT)
    envelope["ciphertext"] = "A" * (MAX_CIPHERTEXT_B64 + 4)
    outcome = decrypt_envelope(server, node.id, task_id, envelope)
    assert outcome.result.reason_code == codes.PAYLOAD_TOO_LARGE


# ------------------------------------------------------------- no leaks


def test_outcome_repr_and_decision_never_contain_plaintext_or_keys(server, server_pub, node, task_id):
    envelope = encrypt_result(server_pub, node.id, task_id, PLAINTEXT)
    outcome = decrypt_envelope(server, node.id, task_id, envelope)
    for text in (repr(outcome), repr(outcome.result.to_decision("result"))):
        assert "celsius" not in text and "answer" not in text
        assert server_pub not in text and envelope["ciphertext"] not in text
    assert outcome.plaintext_sha256 and len(outcome.plaintext_sha256) == 64


# ---------------------------------------------------- server key handling


def test_server_public_key_parsing_is_strict(server_pub):
    assert x25519_public_to_b64(x25519_public_from_b64(server_pub)) == server_pub
    for bad in ("", "short", "!" * 44, None, base64.b64encode(b"x" * 31).decode()):
        with pytest.raises(CryptoKeyError):
            x25519_public_from_b64(bad)


def test_server_key_file_round_trip_and_protection(tmp_path, server):
    path = tmp_path / "keys" / "server_x25519.key"
    save_x25519_private_key(server, path)
    assert x25519_public_to_b64(load_x25519_private_key(path).public_key()) == x25519_public_to_b64(server.public_key())
    with pytest.raises(CryptoKeyError, match="overwrite"):
        save_x25519_private_key(server, path)
    if os.name != "nt":
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
        path.chmod(0o644)
        with pytest.raises(CryptoKeyError, match="permissions"):
            load_x25519_private_key(path)


# ------------------------------------------- the full submission pipeline


class Submission:
    """Builds the signed POST a node would send for a result."""

    def __init__(self, node, server_pub, task_id, plaintext=PLAINTEXT):
        self.node, self.task_id = node, task_id
        self.path = f"/api/v1/node-api/tasks/{task_id}/result/"
        self.envelope = encrypt_result(server_pub, node.id, task_id, plaintext)

    def request(self, envelope=None, *, ts=None, nonce=None):
        body = json.dumps(envelope or self.envelope, separators=(",", ":")).encode()
        headers = sign_request(self.node.key, self.node.id, "POST", self.path, body, timestamp=int(NOW) if ts is None else ts, nonce=nonce)
        return headers, body


def submit(sub, server, store, headers, body, *, assigned="default", now=NOW, **kw):
    assigned = sub.node.id if assigned == "default" else assigned
    return verify_result_request(
        headers, "POST", sub.path, body, sub.node.lookup, store, server, sub.task_id, assigned, now=now, **kw
    )


@pytest.fixture
def sub(node, server_pub, task_id):
    return Submission(node, server_pub, task_id)


@pytest.fixture
def store():
    return InMemoryReplayStore()


def test_honest_submission_is_accepted_and_decrypted(sub, server, store):
    outcome = submit(sub, server, store, *sub.request())
    assert outcome.accepted and outcome.plaintext == PLAINTEXT
    assert [r["rule"] for r in outcome.result.rules_fired] == [
        "headers_present", "node_known", "node_active", "signature_valid",
        "timestamp_window", "nonce_unique", "task_assigned", "envelope_fields_valid", "aes_gcm_tag",
    ]
    assert outcome.result.evidence["task_id"] == sub.task_id


def test_T4_altered_ciphertext_with_a_valid_signature_fails_integrity(sub, server, store):
    """The node signs a request whose ciphertext was changed BEFORE signing: only GCM can catch it."""
    altered = dict(sub.envelope, ciphertext=flip(sub.envelope["ciphertext"]))
    outcome = submit(sub, server, store, *sub.request(altered))
    assert outcome.result.reason_code == codes.RESULT_INTEGRITY_FAILED
    assert outcome.result.rules_fired[3] == {"rule": "signature_valid", "passed": True, "detail": "Ed25519 signature matches the registered key"}


def test_T4_ciphertext_altered_in_transit_fails_the_signature(sub, server, store):
    headers, body = sub.request()
    altered = body.replace(sub.envelope["ciphertext"][:8].encode(), flip(sub.envelope["ciphertext"][:8]).encode(), 1)
    assert altered != body
    outcome = submit(sub, server, store, headers, altered)
    assert outcome.result.reason_code == codes.NODE_SIGNATURE_INVALID


def test_replayed_submission_is_refused_before_any_decryption(sub, server, store):
    headers, body = sub.request()
    assert submit(sub, server, store, headers, body).accepted
    replay = submit(sub, server, store, headers, body)
    assert replay.result.reason_code == codes.HEARTBEAT_REPLAYED
    assert "envelope_fields_valid" not in [r["rule"] for r in replay.result.rules_fired]


def test_stale_submission_is_refused(sub, server, store):
    assert submit(sub, server, store, *sub.request(ts=int(NOW) - 100)).result.reason_code == codes.HEARTBEAT_STALE


def test_task_assigned_to_another_node_is_refused(sub, server, store):
    outcome = submit(sub, server, store, *sub.request(), assigned=str(uuid.uuid4()))
    assert outcome.result.reason_code == codes.RESULT_NOT_ASSIGNED and outcome.plaintext is None


def test_unassigned_task_is_refused(sub, server, store):
    assert submit(sub, server, store, *sub.request(), assigned=None).result.reason_code == codes.RESULT_NOT_ASSIGNED


def test_result_signed_for_another_task_path_fails_the_signature(sub, server, store, server_pub):
    other = Submission(sub.node, server_pub, str(uuid.uuid4()))
    headers, body = other.request()  # signed for a different path
    outcome = submit(sub, server, store, headers, body)
    assert outcome.result.reason_code == codes.NODE_SIGNATURE_INVALID


def test_malformed_json_body_is_refused(sub, server, store):
    body = b"not json"
    headers = sign_request(sub.node.key, sub.node.id, "POST", sub.path, body, timestamp=int(NOW))
    assert submit(sub, server, store, headers, body).result.reason_code == codes.MALFORMED_REQUEST


def test_oversized_body_is_refused_before_crypto(sub, server, store):
    outcome = submit(sub, server, store, {}, b"x" * (MAX_RESULT_BODY_BYTES + 1))
    assert outcome.result.reason_code == codes.PAYLOAD_TOO_LARGE


def test_revoked_node_cannot_submit(server, server_pub, task_id, store):
    revoked = Node(status="revoked")
    s = Submission(revoked, server_pub, task_id)
    assert submit(s, server, store, *s.request()).result.reason_code == codes.NODE_REVOKED


def test_rejected_submissions_leave_the_nonce_store_empty_when_unauthenticated(sub, server, store):
    stranger = Node()
    forged = Submission(stranger, x25519_public_to_b64(server.public_key()), sub.task_id)
    headers, body = forged.request()
    headers["X-Node-Id"] = sub.node.id  # pretend to be the real node, signed with another key
    for _ in range(10):
        assert not submit(sub, server, store, headers, body).accepted
    assert store.nonce_count() == 0