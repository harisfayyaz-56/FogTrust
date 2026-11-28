# Test Evidence: FR-7 Dashboard, Evidence View, and QA

| | |
|---|---|
| Member | Member 4 (Dashboard, Evidence, QA; FR-7) |
| Target Week | Week 3–4 |
| Test Suite | `tests/e2e/dashboard.test.mjs` (Run: `node --test tests/e2e/dashboard.test.mjs`) |
| Results | 7 passed, 0 failed |

---

## 1. Automated QA Test Suite Summary

| # | Test Scenario | Expected Outcome | Actual Result | Status |
|---|---|---|---|---|
| M4-1 | **No `dangerouslySetInnerHTML`** | Static codebase scan verifies zero instances across `frontend/src` | 0 instances found | Pass |
| M4-2 | **Zero Secret Hardcoding** | Static scanner ensures no private keys, secrets, or raw tokens exist in source | 0 private keys or tokens found | Pass |
| M4-3 | **Sanitized Export (API 5.10)** | JSON & CSV export strictly excludes public keys, token hashes, ciphertexts, passwords, and IPs | All 5 sensitive categories absent | Pass |
| M4-4 | **Revocation Safety (T5)** | Requires exact node name match (`confirm_name`) and reason >= 10 chars | `CONFIRMATION_REQUIRED` and `VALIDATION_ERROR` enforced | Pass |
| M4-5 | **Explainable Decision Schema (FR-7)** | Verifies decision contract: rules evaluated, passed booleans, details, latency, and non-secret evidence | Validated against Section 4 shared schema | Pass |
| M4-6 | **Audit Hash Chain Tamper Detection (ID-9)** | Verifies sequential SHA-256 linking and detects modified or missing events | Tampered link correctly flagged at sequence #2 | Pass |
| M4-7 | **Role Capability Matrix Enforcement** | Role permissions strictly align with API Contract Section 3 | Enforced on client presentation and server responses | Pass |

---

## 2. Decision Explanations Observed in Evidence View

| Scenario | Decision | Reason Code | Rules Evaluated | Evidence Retained |
|---|---|---|---|---|
| Normal Heartbeat | `allow` | `OK` | 6 rules passed (signature, timestamp, nonce, counter) | `counter: 42`, `skew_s: 0.4`, `nonce_prefix: "7a1b"` |
| Replayed Nonce (T2) | `deny` | `HEARTBEAT_REPLAYED` | `nonce_unique` failed | `counter: 42`, `nonce_prefix: "7a1b"` |
| Tampered Ciphertext (T4) | `deny` | `RESULT_INTEGRITY_FAILED` | `aes_gcm_tag` failed | `task_id: "task-7701"`, `ephemeral_key_prefix: "4c8e"` |
| Worker Stalling (T3) | `revoke` | `AUTO_REVOKE_THRESHOLD` | `trust_threshold_check` failed | `node_trust_score: 12`, `source: "automatic"` |
| Admin Revocation (T5) | `revoke` | `CONFIRMED_REVOCATION` | `caller_is_admin`, `confirm_name_matches` passed | `node_name: "compromised-node-03"`, `source: "manual"` |
| Task Assignment | `assign` | `OK` | `trust_threshold_check`, `spare_capacity_check` passed | `node_trust_score: 96`, `capacity: 4`, `load: 1` |

---

## 3. Decision Latency Measurements (Frontend Inspection)

Measurements taken over 50 mock and live decision payloads rendered on the dashboard:

| Operation | Subject Type | Median Latency | Max Latency | Safe Non-Secret Evidence Stored |
|---|---|---|---|---|
| Heartbeat Verification | `heartbeat` | 0.18 ms | 0.42 ms | `counter`, `last_counter`, `nonce_prefix`, `skew_s` |
| Task Assignment | `task` | 2.10 ms | 4.80 ms | `node_id`, `trust_score`, `capacity`, `current_load` |
| Result Decryption & Integrity | `result` | 0.09 ms | 0.25 ms | `task_id`, `ephemeral_key_prefix`, `ciphertext_length` |
| Node Revocation | `node` | 1.15 ms | 2.90 ms | `node_name`, `revoked_by`, `source` |

