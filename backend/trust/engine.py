"""
Trust Score Engine (Member 3).

Pure Python with zero Django or web framework dependencies.
Calculates a rule-based trust score (0 to 100) based on historical node behavior
and returns an explainable breakdown of all rules fired.
"""

from __future__ import annotations

import time
from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(frozen=True)
class NodeMetrics:
    missed_heartbeats: int = 0
    signature_failures: int = 0
    task_failures: int = 0
    integrity_failures: int = 0
    task_successes: int = 0
    heartbeat_successes: int = 0
    load_inconsistencies: int = 0


@dataclass
class RuleResult:
    rule: str
    weight: int
    value: int
    contribution: int
    reason: str


@dataclass
class TrustDecision:
    new_score: int
    previous_score: int
    rules_fired: list[dict[str, Any]]
    policy_version: int
    latency_ms: float
    should_auto_revoke: bool
    explanation: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def compute_trust_score(
    current_score: int,
    policy_values: dict[str, Any],
    metrics: NodeMetrics,
    policy_version: int = 1,
) -> TrustDecision:
    """
    Computes new trust score clamped to [0, 100] using configurable policy weights.
    Generates human-readable, explainable records for every rule evaluated.
    """
    start_time = time.perf_counter()

    weights = policy_values.get("weights", {})
    auto_revoke_below = policy_values.get("auto_revoke_below", 10)

    rules_fired: list[RuleResult] = []

    # Rule 1: Missed heartbeats
    if metrics.missed_heartbeats > 0:
        w = weights.get("missed_heartbeat", -10)
        c = w * metrics.missed_heartbeats
        rules_fired.append(
            RuleResult(
                rule="missed_heartbeats",
                weight=w,
                value=metrics.missed_heartbeats,
                contribution=c,
                reason=f"{metrics.missed_heartbeats} missed heartbeat(s) detected",
            )
        )

    # Rule 2: Signature failures (T1 / T2 related)
    if metrics.signature_failures > 0:
        w = weights.get("signature_failure", -20)
        c = w * metrics.signature_failures
        rules_fired.append(
            RuleResult(
                rule="signature_failures",
                weight=w,
                value=metrics.signature_failures,
                contribution=c,
                reason=f"{metrics.signature_failures} signature verification failure(s)",
            )
        )

    # Rule 3: Task worker failures (T3 related)
    if metrics.task_failures > 0:
        w = weights.get("task_failure", -15)
        c = w * metrics.task_failures
        rules_fired.append(
            RuleResult(
                rule="task_failures",
                weight=w,
                value=metrics.task_failures,
                contribution=c,
                reason=f"{metrics.task_failures} task worker failure(s) or stall timeout(s)",
            )
        )

    # Rule 4: Result tampering / integrity failures (T4 related)
    if metrics.integrity_failures > 0:
        w = weights.get("integrity_failure", -25)
        c = w * metrics.integrity_failures
        rules_fired.append(
            RuleResult(
                rule="integrity_failures",
                weight=w,
                value=metrics.integrity_failures,
                contribution=c,
                reason=f"{metrics.integrity_failures} result integrity / decryption failure(s)",
            )
        )

    # Rule 5: Task completions (success)
    if metrics.task_successes > 0:
        w = weights.get("task_success", 5)
        c = w * metrics.task_successes
        rules_fired.append(
            RuleResult(
                rule="task_successes",
                weight=w,
                value=metrics.task_successes,
                contribution=c,
                reason=f"{metrics.task_successes} successful task completion(s)",
            )
        )

    # Rule 6: Accepted heartbeats (success)
    if metrics.heartbeat_successes > 0:
        w = weights.get("heartbeat_success", 2)
        c = w * metrics.heartbeat_successes
        rules_fired.append(
            RuleResult(
                rule="heartbeat_successes",
                weight=w,
                value=metrics.heartbeat_successes,
                contribution=c,
                reason=f"{metrics.heartbeat_successes} valid heartbeat(s) received",
            )
        )

    # Rule 7: Load report inconsistencies
    if metrics.load_inconsistencies > 0:
        w = weights.get("load_inconsistency", -5)
        c = w * metrics.load_inconsistencies
        rules_fired.append(
            RuleResult(
                rule="load_inconsistencies",
                weight=w,
                value=metrics.load_inconsistencies,
                contribution=c,
                reason=f"{metrics.load_inconsistencies} anomaly/anomaly in reported load vs active assignments",
            )
        )

    total_delta = sum(r.contribution for r in rules_fired)
    calculated_score = current_score + total_delta
    new_score = max(0, min(100, calculated_score))

    # Human-readable explanation
    if total_delta > 0:
        explanation = f"Trust increased by {new_score - current_score} point(s) based on positive activity."
    elif total_delta < 0:
        reasons_summary = ", ".join(r.rule for r in rules_fired if r.contribution < 0)
        explanation = f"Trust dropped by {current_score - new_score} point(s) due to: {reasons_summary}."
    else:
        explanation = "Trust score unchanged; no active penalties or rewards applied."

    should_auto_revoke = new_score <= auto_revoke_below
    if should_auto_revoke:
        explanation += f" Score fell to/below auto-revoke threshold ({auto_revoke_below})."

    latency_ms = (time.perf_counter() - start_time) * 1000.0

    return TrustDecision(
        new_score=new_score,
        previous_score=current_score,
        rules_fired=[asdict(r) for r in rules_fired],
        policy_version=policy_version,
        latency_ms=round(latency_ms, 3),
        should_auto_revoke=should_auto_revoke,
        explanation=explanation,
    )

