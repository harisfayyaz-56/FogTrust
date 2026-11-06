"""The result object every verification returns (the shared decision schema, docs/data-model.md section 4)."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from datetime import datetime, timezone

from . import codes

ENGINE_VERSION = "0.2.0"


@dataclass(frozen=True)
class VerificationResult:
    accepted: bool
    reason_code: str  # codes.OK when accepted
    explanation: str  # one safe sentence; never contains user input, keys or tokens
    rules_fired: list = field(default_factory=list)  # every rule evaluated, passed or not
    evidence: dict = field(default_factory=dict)  # non-secret values only
    node_id: str | None = None  # canonical UUID string, once parsed
    timestamp: int | None = None  # claimed Unix time, once parsed
    nonce: str | None = None  # claimed nonce, once parsed
    thresholds: dict = field(default_factory=dict)
    engine_name: str = "node_request_verifier"
    engine_version: str = ENGINE_VERSION
    latency_ms: float = 0.0
    payload: dict | None = None  # validated request body (heartbeats); never part of the decision

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


class Run:
    """
    Builder used by the multi-step verifiers (heartbeat, result). It carries the rules and
    evidence collected so far, optionally continuing from an earlier VerificationResult
    (the signature check), and produces the final deny or allow.
    """

    def __init__(self, engine_name: str, thresholds: dict | None = None, base: VerificationResult | None = None):
        self._started = time.perf_counter()
        self._base_latency = base.latency_ms if base else 0.0
        self.engine_name = engine_name
        self.thresholds = dict(thresholds or {})
        self.rules: list = list(base.rules_fired) if base else []
        self.evidence: dict = dict(base.evidence) if base else {}
        self.node_id = base.node_id if base else None
        self.timestamp = base.timestamp if base else None
        self.nonce = base.nonce if base else None

    def rule(self, name: str, passed: bool, detail: str) -> None:
        self.rules.append({"rule": name, "passed": passed, "detail": detail})

    def _finish(self, accepted, code, explanation, payload, extra) -> VerificationResult:
        evidence = dict(self.evidence)
        evidence.update(extra)
        elapsed = (time.perf_counter() - self._started) * 1000
        return VerificationResult(
            accepted=accepted,
            reason_code=code,
            explanation=explanation,
            rules_fired=self.rules,
            evidence=evidence,
            node_id=self.node_id,
            timestamp=self.timestamp,
            nonce=self.nonce,
            thresholds=self.thresholds,
            engine_name=self.engine_name,
            latency_ms=round(self._base_latency + elapsed, 3),
            payload=payload,
        )

    def deny(self, code: str, explanation: str, **evidence) -> VerificationResult:
        return self._finish(False, code, explanation, None, evidence)

    def allow(self, explanation: str, payload: dict | None = None, **evidence) -> VerificationResult:
        return self._finish(True, codes.OK, explanation, payload, evidence)