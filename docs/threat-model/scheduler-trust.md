# Threat Model: Scheduler and Trust Engine (Member 3)

| | |
|---|---|
| Slice | Member 3 (FR-3 Task Queue, FR-4 Trust Score Engine, Scheduler) |
| Method | STRIDE per trust boundary |
| Version | 0.1 |

This document contributes to the team threat model (at least 8 threats mapped to mitigations).

---

## Threats and Mitigations

| ID | Threat | STRIDE | Boundary | Mitigation | Evidence / Test | Status |
|---|---|---|---|---|---|---|
| ST-1 | **Task flooding**: malicious or compromised operator submits thousands of tasks to exhaust node capacity | Denial of Service | TB1 | Role-based permissions, max task payload size (16 KB), queue priority constraints | `TaskSubmitSerializer` validation | Built |
| ST-2 | **Duplicate submission**: network glitches or malicious retries duplicate a task execution | Tampering | TB1, TB4 | Mandatory `Idempotency-Key` header with database-enforced unique constraint | `DuplicateSubmissionError`, `test_task_submission` | Built |
| ST-3 | **Trust score manipulation**: an edge node attempts to claim high trust or disguise its metrics | Tampering | TB2, TB3 | Trust engine never reads node-submitted trust scores or metrics directly. Metrics (`NodeMetrics`) are compiled strictly from server-side cryptographic and heartbeat audits | `trust.engine.compute_trust_score`, `test_engine.py` | Built |
| ST-4 | **Policy rollback / threshold tampering**: unauthorized tampering of trust criteria to admit compromised nodes | Tampering | TB5 | Policies (`PolicyConfig`) are immutable, append-only with monotonic versions. Updating policies requires Administrator role and mandatory `change_reason`, audited to the hash chain | `PolicyUpdateView`, `trust.services.create_policy`, `audit.models.AuditEvent` | Built |
| ST-5 | **Silent worker stalling (T3)**: a worker node crashes or disconnects while holding in-flight tasks | Denial of Service | TB2 | Automatic stall detection via `detect_stalled_tasks`. Reclaims node capacity, penalizes node trust score, and re-queues task up to `max_attempts` | `tasks.tests.test_scheduler.test_T3_failed_worker_reassigns_task_and_penalizes_node` | Built |
| ST-6 | **Starvation / unbalance in node dispatch (T6)**: naive round-robin assigns tasks to degraded, low-trust, or overwhelmed nodes | Denial of Service | TB3 | Trust-aware load-balancing scheduler: filters nodes strictly by `trust_score >= trust_threshold`, sorts by lowest `current_load` | `tasks.tests.test_scheduler.test_T6_trust_aware_vs_round_robin_load_balancing` | Built |

