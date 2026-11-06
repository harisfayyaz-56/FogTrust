"""T2: replayed heartbeat, plus the other freshness checks. Written against the Week 3 design answers."""

import threading

import pytest

from fogtrust_crypto import codes
from fogtrust_crypto.heartbeat import MAX_HEARTBEAT_BODY_BYTES, parse_heartbeat_body, verify_heartbeat
from fogtrust_crypto.node_auth import HEADER_SIGNATURE
from fogtrust_crypto.replay import InMemoryReplayStore

from .helpers import HEARTBEAT_PATH, NOW, Node, lookup_for


@pytest.fixture
def node():
    return Node()


@pytest.fixture
def store():
    return InMemoryReplayStore()


def verify(node, store, headers, body, **kw):
    kw.setdefault("now", NOW)
    return verify_heartbeat(headers, "POST", HEARTBEAT_PATH, body, node.lookup, store, **kw)


# ------------------------------------------------------------- happy path


def test_valid_heartbeat_is_accepted_and_advances_state(node, store):
    headers, body = node.heartbeat(counter=1)
    result = verify(node, store, headers, body)
    assert result.accepted and result.reason_code == codes.OK
    assert store.last_counter(node.id) == 1 and store.nonce_count() == 1
    assert [r["rule"] for r in result.rules_fired] == [
        "headers_present", "node_known", "node_active", "signature_valid",
        "timestamp_window", "nonce_unique", "body_valid", "counter_increasing",
    ]
    assert result.payload == {"counter": 1, "reported_load": 0, "sent_at": "2026-11-19T10:20:31.000Z"}


def test_counter_may_skip_numbers(node, store):
    assert verify(node, store, *node.heartbeat(counter=1)).accepted
    assert verify(node, store, *node.heartbeat(counter=50)).accepted


# ------------------------------------------------------- timestamp window


@pytest.mark.parametrize("offset,accepted", [(0, True), (-30, True), (30, True), (-31, False), (31, False), (-3600, False)])
def test_timestamp_window_boundaries(node, store, offset, accepted):
    result = verify(node, store, *node.heartbeat(ts=int(NOW) + offset))
    assert result.accepted is accepted
    if not accepted:
        assert result.reason_code == codes.HEARTBEAT_STALE
        assert result.evidence["skew_s"] == -offset


def test_stale_denial_explains_skew_and_limit(node, store):
    result = verify(node, store, *node.heartbeat(ts=int(NOW) - 100))
    rule = result.rules_fired[-1]
    assert rule["rule"] == "timestamp_window" and rule["passed"] is False
    assert rule["detail"] == "skew +100.0 s, limit 30 s"


def test_window_comes_from_policy(node, store):
    headers, body = node.heartbeat(ts=int(NOW) - 6)
    result = verify(node, store, headers, body, window_s=5)
    assert result.reason_code == codes.HEARTBEAT_STALE
    assert result.to_decision("heartbeat")["thresholds"]["timestamp_window_s"] == 5


# ---------------------------------------------------------------- T2 core


def test_T2_exact_replay_is_rejected_with_the_nonce_reason(node, store):
    headers, body = node.heartbeat(counter=1)
    assert verify(node, store, headers, body).accepted
    replay = verify(node, store, headers, body)
    assert not replay.accepted and replay.reason_code == codes.HEARTBEAT_REPLAYED
    assert replay.rules_fired[-1] == {
        "rule": "nonce_unique", "passed": False, "detail": "nonce already used by this node inside the window",
    }
    assert replay.rules_fired[3]["rule"] == "signature_valid" and replay.rules_fired[3]["passed"]  # the copy IS validly signed


def test_replay_later_than_the_window_is_stale_not_replayed(node, store):
    headers, body = node.heartbeat(counter=1)
    assert verify(node, store, headers, body).accepted
    late = verify(node, store, headers, body, now=NOW + 31)
    assert late.reason_code == codes.HEARTBEAT_STALE


def test_same_nonce_with_a_new_counter_is_still_replayed(node, store):
    nonce = "ab" * 16
    assert verify(node, store, *node.heartbeat(counter=1, nonce=nonce)).accepted
    again = verify(node, store, *node.heartbeat(counter=2, nonce=nonce))
    assert again.reason_code == codes.HEARTBEAT_REPLAYED


def test_nonces_are_per_node(store):
    a, b = Node(), Node()
    lookup = lookup_for(a, b)
    nonce = "cd" * 16
    for n in (a, b):
        headers, body = n.heartbeat(counter=1, nonce=nonce)
        assert verify_heartbeat(headers, "POST", HEARTBEAT_PATH, body, lookup, store, now=NOW).accepted


# ---------------------------------------------------------------- counter


@pytest.mark.parametrize("second", [5, 4, 1])
def test_counter_equal_or_lower_is_rejected(node, store, second):
    assert verify(node, store, *node.heartbeat(counter=5)).accepted
    result = verify(node, store, *node.heartbeat(counter=second))  # fresh nonce, validly signed
    assert result.reason_code == codes.HEARTBEAT_COUNTER_REGRESSED
    assert result.evidence["counter"] == second and result.evidence["last_counter"] == 5


def test_rejected_regression_does_not_move_the_counter(node, store):
    assert verify(node, store, *node.heartbeat(counter=5)).accepted
    verify(node, store, *node.heartbeat(counter=3))
    assert store.last_counter(node.id) == 5


# ------------------------------------- rejected requests change no state


def test_stale_heartbeat_leaves_the_store_untouched(node, store):
    verify(node, store, *node.heartbeat(ts=int(NOW) - 100))
    assert store.last_counter(node.id) == 0 and store.nonce_count() == 0


def test_bad_signature_cannot_fill_the_nonce_store(node, store):
    stranger = Node().key
    for _ in range(25):
        assert not verify(node, store, *node.heartbeat(key=stranger)).accepted
    assert store.nonce_count() == 0 and store.last_counter(node.id) == 0


def test_revoked_and_unknown_nodes_leave_the_store_untouched(store):
    revoked = Node(status="revoked")
    assert verify(revoked, store, *revoked.heartbeat()).reason_code == codes.NODE_REVOKED
    ghost = Node()
    unknown = verify_heartbeat(*ghost.heartbeat()[:1], "POST", HEARTBEAT_PATH, b"{}", revoked.lookup, store, now=NOW)
    assert not unknown.accepted
    assert store.nonce_count() == 0


# ----------------------------------------------------------- body checks


@pytest.mark.parametrize(
    "body,code",
    [
        (b"not json", codes.MALFORMED_REQUEST),
        (b"\xff\xfe", codes.MALFORMED_REQUEST),
        (b"[]", codes.VALIDATION_ERROR),
        (b'{"counter":1,"reported_load":0}', codes.VALIDATION_ERROR),
        (b'{"counter":1,"reported_load":0,"sent_at":"2026-11-19T10:20:31Z","admin":true}', codes.VALIDATION_ERROR),
        (b'{"counter":1.0,"reported_load":0,"sent_at":"2026-11-19T10:20:31Z"}', codes.VALIDATION_ERROR),
        (b'{"counter":true,"reported_load":0,"sent_at":"2026-11-19T10:20:31Z"}', codes.VALIDATION_ERROR),
        (b'{"counter":0,"reported_load":0,"sent_at":"2026-11-19T10:20:31Z"}', codes.VALIDATION_ERROR),
        (b'{"counter":-1,"reported_load":0,"sent_at":"2026-11-19T10:20:31Z"}', codes.VALIDATION_ERROR),
        (b'{"counter":1,"reported_load":-1,"sent_at":"2026-11-19T10:20:31Z"}', codes.VALIDATION_ERROR),
        (b'{"counter":1,"reported_load":99999,"sent_at":"2026-11-19T10:20:31Z"}', codes.VALIDATION_ERROR),
        (b'{"counter":1,"reported_load":0,"sent_at":"yesterday"}', codes.VALIDATION_ERROR),
        (b'{"counter":1,"reported_load":0,"sent_at":5}', codes.VALIDATION_ERROR),
    ],
)
def test_bad_bodies_are_rejected_by_the_parser(body, code):
    assert parse_heartbeat_body(body)[1] == code


def test_signed_but_invalid_body_is_rejected_end_to_end(node, store):
    from fogtrust_crypto.node_auth import sign_request

    body = b'{"counter":1,"reported_load":0,"sent_at":"2026-11-19T10:20:31Z","admin":true}'
    headers = sign_request(node.key, node.id, "POST", HEARTBEAT_PATH, body, timestamp=int(NOW))
    result = verify(node, store, headers, body)
    assert result.reason_code == codes.VALIDATION_ERROR and store.last_counter(node.id) == 0


def test_oversized_body_is_refused_before_any_crypto(node, store):
    headers = {"X-Node-Id": "garbage"}
    result = verify(node, store, headers, b"x" * (MAX_HEARTBEAT_BODY_BYTES + 1))
    assert result.reason_code == codes.PAYLOAD_TOO_LARGE
    assert [r["rule"] for r in result.rules_fired] == ["body_size"]


def test_body_at_the_limit_is_not_refused_for_size(node, store):
    result = verify(node, store, {}, b"x" * MAX_HEARTBEAT_BODY_BYTES)
    assert result.reason_code == codes.NODE_SIGNATURE_MISSING


# ------------------------------------------------- purge and concurrency


def test_nonces_are_purged_only_after_their_window(node, store):
    headers, body = node.heartbeat()
    assert verify(node, store, headers, body).accepted
    assert store.purge(NOW + 30) == 0  # still inside the window: must be kept
    assert store.nonce_count() == 1
    assert store.purge(NOW + 31) == 1
    assert store.nonce_count() == 0


def test_identical_requests_sent_at_the_same_moment_are_accepted_exactly_once(node, store):
    headers, body = node.heartbeat()
    results, barrier = [], threading.Barrier(20)

    def send():
        barrier.wait()
        results.append(verify(node, store, headers, body))

    threads = [threading.Thread(target=send) for _ in range(20)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert sum(r.accepted for r in results) == 1
    assert sum(r.reason_code == codes.HEARTBEAT_REPLAYED for r in results) == 19


def test_two_requests_with_the_same_counter_and_different_nonces_race_safely(node, store):
    prepared = [node.heartbeat(counter=7) for _ in range(20)]
    results, barrier = [], threading.Barrier(20)

    def send(pair):
        barrier.wait()
        results.append(verify(node, store, *pair))

    threads = [threading.Thread(target=send, args=(p,)) for p in prepared]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert sum(r.accepted for r in results) == 1
    assert sum(r.reason_code == codes.HEARTBEAT_COUNTER_REGRESSED for r in results) == 19


# --------------------------------------------------------------- decisions


def test_replay_decision_has_the_shared_schema_and_no_secrets(node, store):
    headers, body = node.heartbeat()
    verify(node, store, headers, body)
    decision = verify(node, store, headers, body).to_decision("heartbeat")
    assert decision["decision"] == "deny" and decision["reason_code"] == codes.HEARTBEAT_REPLAYED
    assert decision["engine_name"] == "heartbeat_verifier"
    text = repr(decision)
    assert headers[HEADER_SIGNATURE] not in text and node.info.public_key not in text
    assert headers["X-Node-Nonce"] not in text  # only a 4-character prefix is shown