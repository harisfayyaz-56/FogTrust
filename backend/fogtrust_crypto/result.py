"""The result object every verification returns (the shared decision schema, docs/data-model.md section 4)."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

from . import codes


@dataclass(frozen=True)
class VerificationResult:
    accepted: bool
    reason_code: str  # codes.OK when accepted
    explanation: str  # one safe sentence; never contains user input, keys or tokens
    rules_fired: list = field(default_factory=list)  # every rule evaluated, passed or not
    evidence: dict = field(default_factory=dict)  # non-secret values only
    node_id: str | None = None  # canonical UUID string, once parsed
    timestamp: int | None = None  # claimed Unix time, once parsed (for the replay checks)
    nonce: str | None = None  # claimed nonce, once parsed (for the replay checks)
    thresholds: dict = field(default_factory=dict)
    engine_name: str = "node_request_verifier"
    engine_version: str = "0.1.0"
    latency_ms: float = 0.0

    def to_decision(self, subject_type: str, subject_id: str | None = None) -> dict:
        """
        Convert to the shared Decision dict. The caller (API layer) adds
        `decision_id` and `request_id` before storing it.
        """
        return {
            "subject_type": subject_type,
            "subject_id": subject_id or self.node_id or "",
            "decision": "allow" if self.accepted else "deny",
            "reason_code": self.reason_code if not self.accepted else codes.OK,
            "explanation": self.explanation,
            "rules_fired": list(self.rules_fired),
            "evidence": dict(self.evidence),
            "engine_name": self.engine_name,
            "engine_version": self.engine_version,
            "policy_version": None,
            "thresholds": dict(self.thresholds),
            "decided_at": datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z"),
            "latency_ms": self.latency_ms,
        }