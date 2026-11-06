"""
Full heartbeat verification (FR-2, test T2).

Order: size limit, then the contract's steps 1 to 6 (headers, node exists, node active, signature,
timestamp window, nonce), then the two heartbeat-specific checks (body valid, counter increasing).
The counter lives in the JSON body, which the generic verifier does not know, so it is checked here.
"""

from __future__ import annotations

import json
import time
from datetime import datetime
from typing import Mapping, Optional

from . import codes
from .node_auth import NodeLookup, verify_node_request
from .replay import DEFAULT_WINDOW_S, ReplayStore, check_freshness, check_nonce
from .result import Run, VerificationResult

MAX_HEARTBEAT_BODY_BYTES = 2048
HEARTBEAT_FIELDS = frozenset({"counter", "reported_load", "sent_at"})
MAX_COUNTER = 2**63 - 1  # database bigint
MAX_LOAD = 32767  # database smallint


def parse_heartbeat_body(body: bytes) -> tuple[Optional[dict], Optional[str], str]:
    """Return (data, None, "") when valid, else (None, reason_code, detail). Never raises."""
    try:
        data = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError):
        return None, codes.MALFORMED_REQUEST, "body is not valid JSON"
    if not isinstance(data, dict):
        return None, codes.VALIDATION_ERROR, "body must be a JSON object"
    if set(data) != HEARTBEAT_FIELDS:
        return None, codes.VALIDATION_ERROR, "body must contain exactly counter, reported_load, sent_at"
    counter, load, sent_at = data["counter"], data["reported_load"], data["sent_at"]
    if isinstance(counter, bool) or not isinstance(counter, int) or not 1 <= counter <= MAX_COUNTER:
        return None, codes.VALIDATION_ERROR, "counter must be an integer from 1 up"
    if isinstance(load, bool) or not isinstance(load, int) or not 0 <= load <= MAX_LOAD:
        return None, codes.VALIDATION_ERROR, "reported_load must be a non-negative integer"
    if not isinstance(sent_at, str) or len(sent_at) > 40:
        return None, codes.VALIDATION_ERROR, "sent_at must be an ISO 8601 time"
    try:
        datetime.fromisoformat(sent_at)
    except ValueError:
        return None, codes.VALIDATION_ERROR, "sent_at must be an ISO 8601 time"
    return data, None, ""


def verify_heartbeat(
    headers: Mapping[str, str],
    method: str,
    path: str,
    body: bytes,
    lookup: NodeLookup,
    store: ReplayStore,
    *,
    window_s: int = DEFAULT_WINDOW_S,
    now: Optional[float] = None,
) -> VerificationResult:
    """
    Verify one heartbeat and, only if every check passes, advance the replay state.

    `window_s` comes from the admin policy (`timestamp_window_s`); `now` is injectable for tests.
    The caller must read the raw body first (Django: request.body before request.data).
    """
    now = time.time() if now is None else now
    thresholds = {"timestamp_window_s": window_s, "max_body_bytes": MAX_HEARTBEAT_BODY_BYTES}

    if len(body) > MAX_HEARTBEAT_BODY_BYTES:
        run = Run("heartbeat_verifier", thresholds)
        run.rule("body_size", False, f"limit {MAX_HEARTBEAT_BODY_BYTES} bytes")
        return run.deny(codes.PAYLOAD_TOO_LARGE, "The request body is too large.")

    base = verify_node_request(headers, method, path, body, lookup)
    if not base.accepted:
        return base
    run = Run("heartbeat_verifier", thresholds, base)

    denial = check_freshness(run, now, window_s) or check_nonce(run, store, window_s)
    if denial:
        return denial

    data, code, detail = parse_heartbeat_body(body)
    if code:
        run.rule("body_valid", False, detail)
        return run.deny(code, "The heartbeat body is invalid.")
    run.rule("body_valid", True, "body has exactly the agreed fields and types")

    if not store.advance_counter(run.node_id, data["counter"]):
        run.rule("counter_increasing", False, "counter is not greater than the last accepted counter")
        return run.deny(
            codes.HEARTBEAT_COUNTER_REGRESSED,
            "The heartbeat counter did not increase.",
            counter=data["counter"],
            last_counter=store.last_counter(run.node_id),
        )
    run.rule("counter_increasing", True, "counter is greater than the last accepted counter")
    return run.allow("Heartbeat accepted.", payload=data, counter=data["counter"], reported_load=data["reported_load"])