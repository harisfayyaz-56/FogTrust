"""
Writing and reading Decisions.

Every slice records its decisions the same way:

    from core.decisions import record_decision, record_decision_dict

    # your own engine
    record_decision(subject_type="task", subject_id=str(task.id), decision="assign",
                    reason_code="OK", explanation="Lowest load among eligible nodes.",
                    rules_fired=[...], evidence={...},
                    engine_name="scheduler", engine_version="1.0.0",
                    policy_version=policy.version, request=request)

    # Member 2's engine already returns the decision shape:
    record_decision_dict(result.to_decision("heartbeat"), request=request)

Evidence is passed through the audit redaction rules first (keys that look like
secrets are replaced, long strings cut), so a careless caller cannot put a key or
token into the evidence view. Decisions are written inside the caller's transaction
when there is one, so a decision and the action it describes succeed or fail together.
"""

from __future__ import annotations

from django.utils import timezone
from django.utils.dateparse import parse_datetime

from audit.redaction import redact

from .models import Decision

MAX_EXPLANATION = 500
MAX_RULES = 50


def _clean_rules(rules) -> list:
    cleaned = []
    for item in list(rules or [])[:MAX_RULES]:
        if not isinstance(item, dict):
            continue
        cleaned.append(
            {
                "rule": str(item.get("rule", ""))[:64],
                "passed": bool(item.get("passed")),
                "detail": str(item.get("detail", ""))[:256],
            }
        )
    return cleaned


def record_decision(
    *,
    subject_type: str,
    subject_id: str = "",
    decision: str,
    reason_code: str = "OK",
    explanation: str,
    rules_fired=None,
    evidence: dict | None = None,
    engine_name: str,
    engine_version: str,
    thresholds: dict | None = None,
    policy_version: int | None = None,
    request=None,
    latency_ms: float = 0.0,
    decided_at=None,
) -> Decision:
    if subject_type not in Decision.SubjectType.values:
        raise ValueError(f"subject_type must be one of {Decision.SubjectType.values}")
    if decision not in Decision.Verdict.values:
        raise ValueError(f"decision must be one of {Decision.Verdict.values}")

    return Decision.objects.create(
        subject_type=subject_type,
        subject_id=str(subject_id or "")[:64],
        decision=decision,
        reason_code=str(reason_code or "OK")[:48],
        explanation=str(explanation)[:MAX_EXPLANATION],
        rules_fired=_clean_rules(rules_fired),
        evidence=redact(evidence or {}),
        engine_name=str(engine_name)[:48],
        engine_version=str(engine_version)[:16],
        policy_version=policy_version,
        thresholds=redact(thresholds or {}),
        request_id=str(getattr(request, "request_id", "") or "")[:36],
        decided_at=decided_at or timezone.now(),
        latency_ms=round(float(latency_ms or 0.0), 3),
    )


def record_decision_dict(data: dict, *, request=None) -> Decision:
    """Store a decision dict in the shared schema (e.g. VerificationResult.to_decision())."""
    decided_at = data.get("decided_at")
    if isinstance(decided_at, str):
        decided_at = parse_datetime(decided_at)
    return record_decision(
        subject_type=data["subject_type"],
        subject_id=data.get("subject_id", ""),
        decision=data["decision"],
        reason_code=data.get("reason_code", "OK"),
        explanation=data.get("explanation", ""),
        rules_fired=data.get("rules_fired"),
        evidence=data.get("evidence"),
        engine_name=data.get("engine_name", "unknown"),
        engine_version=data.get("engine_version", "0"),
        thresholds=data.get("thresholds"),
        policy_version=data.get("policy_version"),
        request=request,
        latency_ms=data.get("latency_ms", 0.0),
        decided_at=decided_at,
    )
