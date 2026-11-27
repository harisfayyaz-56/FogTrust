"""
C1: fuzzing. Thousands of mutated and random inputs through every function that touches untrusted data.

Rules checked on EVERY input:
  1. nothing raises (a crash would be a 500 and a denial of service);
  2. a mutated request is never accepted (only the untouched original may be);
  3. every result has a known reason code and a decision that can be turned into JSON.

The seed is fixed, so a failure is reproducible: rerun and the same input appears.
"""

import json
import random
import uuid

import pytest

from fogtrust_crypto import codes
from fogtrust_crypto.heartbeat import MAX_HEARTBEAT_BODY_BYTES, verify_heartbeat
from fogtrust_crypto.keys import (
    CryptoKeyError,
    generate_x25519_private_key,
    public_key_from_b64,
    verify_enrollment_proof,
    x25519_public_from_b64,
    x25519_public_to_b64,
)
from fogtrust_crypto.node_auth import build_string_to_sign, verify_node_request
from fogtrust_crypto.replay import InMemoryReplayStore
from fogtrust_crypto.results import decrypt_envelope, encrypt_result, verify_result_request

from .helpers import HEARTBEAT_PATH, NOW, Node

SEED = 20261107
ITERATIONS = 2500
KNOWN_CODES = set(codes.ALL_CODES) | {codes.OK}
POOL = ["\n", "\r", "\x00", " ", "\t", "%", "=", "/", "\\", "é", "٣", "\u202e", "😀", "'", '"', ";", "-", "+", "0", "9", "a", "Z"]


def mutate_text(rng: random.Random, text: str) -> str:
    op = rng.randrange(9)
    if not text:
        return rng.choice(POOL)
    i = rng.randrange(len(text))
    if op == 0:
        return text[:i] + rng.choice(POOL) + text[i + 1 :]  # replace one character
    if op == 1:
        return text[:i] + text[i + 1 :]  # delete one
    if op == 2:
        return text[:i] + rng.choice(POOL) + text[i:]  # insert one
    if op == 3:
        return text[:i]  # truncate
    if op == 4:
        return text + rng.choice(POOL)  # append (trailing newline, space ...)
    if op == 5:
        return rng.choice(POOL) + text  # prepend
    if op == 6:
        return text * 50  # repeat
    if op == 7:
        return text.swapcase() if text.swapcase() != text else text + "x"
    return ""


def mutate_bytes(rng: random.Random, data: bytes) -> bytes:
    op = rng.randrange(5)
    if not data:
        return bytes([rng.randrange(256)])
    i = rng.randrange(len(data))
    if op == 0:
        return data[:i] + bytes([data[i] ^ (1 << rng.randrange(8))]) + data[i + 1 :]  # flip a bit
    if op == 1:
        return data[:i] + data[i + 1 :]
    if op == 2:
        return data[:i] + bytes([rng.randrange(256)]) + data[i:]
    if op == 3:
        return data[:i]
    return data + bytes(rng.randrange(256) for _ in range(rng.randrange(1, 8)))


def check_result(result):
    assert result.reason_code in KNOWN_CODES, result.reason_code
    json.dumps(result.to_decision("heartbeat"))  # must be serialisable


def garbage_value(rng):
    return rng.choice(
        [None, 0, 1, -1, 3.14, True, b"bytes", [], {}, ["a"], "", " ", "x" * 5000, "\n", str(uuid.uuid4()), "é" * 40, rng.getrandbits(256)]
    )


# ------------------------------------------------------------ heartbeats


def test_mutated_heartbeats_are_never_accepted_and_never_crash():
    rng = random.Random(SEED)
    node = Node()
    headers, body = node.heartbeat(counter=1)
    original = (dict(headers), body, "POST", HEARTBEAT_PATH)
    checked = 0
    for _ in range(ITERATIONS):
        h, b, method, path = dict(headers), body, "POST", HEARTBEAT_PATH
        target = rng.choice(list(h) + ["body", "path", "method"])
        if target == "body":
            b = mutate_bytes(rng, b)
        elif target == "path":
            path = mutate_text(rng, path)
        elif target == "method":
            method = mutate_text(rng, method)
        else:
            h[target] = mutate_text(rng, h[target])
        if (h, b, method, path) == original:
            continue
        result = verify_heartbeat(h, method, path, b, node.lookup, InMemoryReplayStore(), now=NOW)
        check_result(result)
        assert not result.accepted, f"ACCEPTED a mutated request: target={target} headers={h} body={b!r} method={method!r} path={path!r}"
        checked += 1
    assert checked > ITERATIONS * 0.9


def test_random_garbage_headers_and_bodies_never_crash_or_pass():
    rng = random.Random(SEED + 1)
    node = Node()
    names = ["X-Node-Id", "X-Node-Timestamp", "X-Node-Nonce", "X-Node-Signature", "x-node-id", "Content-Type", "X-Other"]
    for _ in range(ITERATIONS):
        headers = {rng.choice(names): garbage_value(rng) for _ in range(rng.randrange(0, 6))}
        body = bytes(rng.randrange(256) for _ in range(rng.choice([0, 1, 10, 200, MAX_HEARTBEAT_BODY_BYTES, MAX_HEARTBEAT_BODY_BYTES + 1])))
        result = verify_heartbeat(headers, rng.choice(["POST", "GET", "", "x"]), rng.choice([HEARTBEAT_PATH, "", "/", "\n"]), body, node.lookup, InMemoryReplayStore(), now=NOW)
        check_result(result)
        assert not result.accepted


def test_heartbeat_with_random_valid_looking_bodies_never_crashes():
    """Signed by the real node, so the body reaches the parser. Only exactly-valid bodies may be accepted."""
    from fogtrust_crypto.node_auth import sign_request

    rng = random.Random(SEED + 2)
    node = Node()
    base = {"counter": 1, "reported_load": 0, "sent_at": "2026-11-19T10:20:31Z"}
    for _ in range(ITERATIONS):
        doc = dict(base)
        for _ in range(rng.randrange(0, 3)):
            key = rng.choice(list(base) + ["extra", ""])
            doc[key] = garbage_value(rng)
        try:
            raw = json.dumps(doc).encode()
        except (TypeError, ValueError):
            continue
        if rng.random() < 0.2:
            raw = mutate_bytes(rng, raw)
        headers = sign_request(node.key, node.id, "POST", HEARTBEAT_PATH, raw, timestamp=int(NOW))
        result = verify_heartbeat(headers, "POST", HEARTBEAT_PATH, raw, node.lookup, InMemoryReplayStore(), now=NOW)
        check_result(result)
        if result.accepted:  # then the body must truly be the agreed shape
            assert set(result.payload) == {"counter", "reported_load", "sent_at"}
            assert type(result.payload["counter"]) is int and result.payload["counter"] >= 1


# ---------------------------------------------------------------- results


def test_mutated_result_submissions_are_never_accepted_and_never_crash():
    from fogtrust_crypto.node_auth import sign_request

    rng = random.Random(SEED + 3)
    server = generate_x25519_private_key()
    node = Node()
    task_id = str(uuid.uuid4())
    path = f"/api/v1/node-api/tasks/{task_id}/result/"
    envelope = encrypt_result(x25519_public_to_b64(server.public_key()), node.id, task_id, b'{"answer": 42}')
    body = json.dumps(envelope, separators=(",", ":")).encode()
    headers = sign_request(node.key, node.id, "POST", path, body, timestamp=int(NOW))
    original = (dict(headers), body, path)
    for _ in range(ITERATIONS):
        h, b, p = dict(headers), body, path
        target = rng.choice(list(h) + ["body", "path"])
        if target == "body":
            b = mutate_bytes(rng, b)
        elif target == "path":
            p = mutate_text(rng, p)
        else:
            h[target] = mutate_text(rng, h[target])
        if (h, b, p) == original:
            continue
        outcome = verify_result_request(h, "POST", p, b, node.lookup, InMemoryReplayStore(), server, task_id, node.id, now=NOW)
        check_result(outcome.result)
        assert not outcome.accepted and outcome.plaintext is None, f"ACCEPTED: target={target} headers={h} body={b!r} path={p!r}"


def test_random_envelopes_never_crash_and_never_decrypt():
    rng = random.Random(SEED + 4)
    server = generate_x25519_private_key()
    node_id, task_id = str(uuid.uuid4()), str(uuid.uuid4())
    for _ in range(ITERATIONS):
        envelope = rng.choice(
            [
                {k: garbage_value(rng) for k in ("ephemeral_public_key", "nonce", "ciphertext")},
                {k: garbage_value(rng) for k in rng.sample(["ephemeral_public_key", "nonce", "ciphertext", "extra"], rng.randrange(0, 4))},
                garbage_value(rng),
            ]
        )
        outcome = decrypt_envelope(server, node_id, task_id, envelope)
        check_result(outcome.result)
        assert not outcome.accepted


# ------------------------------------------------------ small parsers


def test_key_parsers_raise_only_their_own_error():
    rng = random.Random(SEED + 5)
    for _ in range(ITERATIONS):
        value = garbage_value(rng) if rng.random() < 0.5 else mutate_text(rng, "A" * 43 + "=")
        for parse in (public_key_from_b64, x25519_public_from_b64):
            try:
                parse(value)
            except CryptoKeyError:
                pass


def test_enrollment_proof_verifier_never_raises():
    rng = random.Random(SEED + 6)
    for _ in range(ITERATIONS):
        args = [garbage_value(rng) if rng.random() < 0.5 else mutate_text(rng, "A" * 44) for _ in range(4)]
        assert verify_enrollment_proof(*args) is False


def test_string_to_sign_raises_only_value_error():
    rng = random.Random(SEED + 7)
    for _ in range(ITERATIONS):
        try:
            build_string_to_sign(garbage_value(rng), garbage_value(rng), garbage_value(rng), garbage_value(rng), garbage_value(rng))
        except ValueError:
            pass


def test_generic_verifier_never_raises_on_garbage():
    rng = random.Random(SEED + 8)
    node = Node()
    for _ in range(ITERATIONS):
        headers = {n: garbage_value(rng) for n in ("X-Node-Id", "X-Node-Timestamp", "X-Node-Nonce", "X-Node-Signature") if rng.random() < 0.9}
        result = verify_node_request(headers, garbage_value(rng), garbage_value(rng), rng.choice([b"", b"{}", garbage_value(rng)]), node.lookup)
        check_result(result)
        assert not result.accepted