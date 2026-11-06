"""
SHA-256 hash chain for the audit log (docs/data-model.md, section 5.2).

    canonical = JSON of every chained field, keys sorted, separators (",", ":")
    hash      = SHA-256( prev_hash + "\\n" + canonical )   -> lowercase hex

Each event stores the hash of the event before it. Editing, inserting or
deleting a past event breaks the link to the next one, and verify_chain()
reports the first sequence number where that happens.

This module has no Django imports so the rule can be read and tested on its own.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone

GENESIS_HASH = "0" * 64

# Every field that goes into the hash, in a fixed list. `hash` itself is not included.
CHAIN_FIELDS = (
    "sequence",
    "event_id",
    "timestamp",
    "actor_type",
    "actor_id",
    "actor_role",
    "action",
    "target_type",
    "target_id",
    "outcome",
    "reason_code",
    "request_id",
    "source_ip",
    "details",
    "prev_hash",
)


def format_timestamp(value: datetime) -> str:
    """ISO 8601 in UTC with microseconds and a Z, so every machine prints the same text."""
    if value.tzinfo is None:
        raise ValueError("audit timestamps must be timezone-aware")
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def canonical_bytes(fields: dict) -> bytes:
    payload = {}
    for name in CHAIN_FIELDS:
        value = fields[name]
        if name == "timestamp":
            value = format_timestamp(value)
        elif name == "event_id":
            value = str(value)
        elif value is None:
            value = ""
        payload[name] = value
    # ensure_ascii=True (the default) escapes every non-ASCII character, so the bytes
    # are identical on every OS and odd input can never break the encoding.
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("ascii")


def compute_hash(fields: dict) -> str:
    prev_hash = fields["prev_hash"]
    return hashlib.sha256(prev_hash.encode("ascii") + b"\n" + canonical_bytes(fields)).hexdigest()


@dataclass(frozen=True)
class ChainReport:
    valid: bool
    events_checked: int
    first_broken_sequence: int | None = None
    problem: str | None = None  # "link_mismatch", "hash_mismatch" or "sequence_gap"

    def as_dict(self) -> dict:
        return asdict(self)


def verify_rows(rows) -> ChainReport:
    """
    Check an iterable of event dicts (CHAIN_FIELDS plus "hash"), ordered by sequence.

    Problems, checked in this order for each event:
      sequence_gap   a sequence number is missing (an event was deleted)
      link_mismatch  prev_hash is not the hash of the event before
      hash_mismatch  the event's content no longer matches its stored hash
    """
    expected_prev = GENESIS_HASH
    expected_sequence = None
    checked = 0
    for row in rows:
        checked += 1
        sequence = row["sequence"]
        if expected_sequence is not None and sequence != expected_sequence:
            return ChainReport(False, checked, sequence, "sequence_gap")
        if row["prev_hash"] != expected_prev:
            return ChainReport(False, checked, sequence, "link_mismatch")
        if compute_hash(row) != row["hash"]:
            return ChainReport(False, checked, sequence, "hash_mismatch")
        expected_prev = row["hash"]
        expected_sequence = sequence + 1
    return ChainReport(True, checked)
