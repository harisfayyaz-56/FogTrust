# Test plan and results: the mandatory cases, with links to the evidence

Date: 2026-11-15. Run `python -m pytest` from the repository root. Result on this date: **804 passed, 0 failed, 0 skipped on Linux** (Windows skips 3 tests that need POSIX file permissions). The brief requires at least 80 % passing: 100 %.

## 1. The seven mandatory cases

| Case | What is shown | Owner | Tests (file::name or class) | Evidence document | Result |
|---|---|---|---|---|---|
| **T1** spoofed node | A wrong-key request is refused with the exact reason; no state changes; the victim's trust is untouched | Faiqa, Ayesha | `test_heartbeat_api.py::TestT1SpoofedNode` (5), `test_node_auth.py` spoof tests, `test_trust_integration.py::TestAnAttackerCannotPoisonAVictimsTrust` (4), `test_attackers_e2e.py::test_T1_spoofer_is_rejected` | `heartbeat-endpoint.md`, `live-demo.md` step 3 | Pass |
| **T2** replayed heartbeat | Exact copy refused (nonce), old capture refused (window), counter going back refused; atomic under simultaneous copies; survives a restart | Faiqa | `test_heartbeat_api.py::TestT2ReplayedHeartbeat` (4), `test_replay_is_still_refused_after_a_restart`, `test_replay.py` (41), `TestAtomicity` (5) | `crypto-T2-T4.md`, `heartbeat-endpoint.md`, `live-demo.md` steps 6 to 8 | Pass |
| **T3** failed worker | A crashed worker is detected, its task moves, the other worker completes it; replays cannot keep a dead worker alive | Haris, Faiqa | `test_t3_failed_worker.py` (3), `test_scheduler.py` | `integration-t3-trust.md`, fleet run in `heartbeat-endpoint.md` section 3 | Pass |
| **T4** altered result | A changed ciphertext is detected in transit (signature), before signing (AES-GCM) and at rest (read-time decrypt); kept as evidence; costs trust | Faiqa | `test_results.py::T4`, `test_result_api.py::TestT4AlteredResult` (4), `test_tampering_with_the_stored_ciphertext_is_caught_when_it_is_read`, `TestIntegrityFailureCostsTrust` (3) | `crypto-T2-T4.md`, `results-endpoint.md`, `live-demo.md` steps 11 and 12 | Pass |
| **T5** revocation | A revoked node is refused on its next request; repeated tampering revokes automatically | Ayesha, Faiqa | `test_revocation.py` (31), `TestT5Revocation`, `test_repeated_tampering_ends_in_automatic_revocation` | `identity-T1-T5.md`, `heartbeat-endpoint.md` | Pass |
| **T6** load balancing | Tasks go to the eligible node with the lowest load; a node that finishes tasks has room again | Haris | `tasks/tests/` (scheduler), `test_a_node_that_keeps_finishing_tasks_is_never_full` | Haris's evidence; load-slot fix in `integration-t3-trust.md` | Pass (Haris's comparison against round-robin is his to report) |
| **T-final** | Oversized and malformed input, unauthorized request, repeated submission, safe failure, recovery after restart | all | see section 2 | `crypto-hardening.md`, `heartbeat-endpoint.md`, `results-endpoint.md` | Pass |

## 2. T-final, item by item (crypto endpoints)

| Item | Test |
|---|---|
| Oversized input | `test_oversized_body_is_refused_before_it_is_read` (heartbeat and result), `test_declared_length_check`, `test_oversized_ciphertext_is_refused_before_decoding` |
| Malformed input | `test_signed_but_malformed_json_is_refused`, `test_signed_but_invalid_body_is_refused`, `test_malformed_envelopes_fail_safely`, `test_fuzz.py` (9 tests, about 22,500 inputs) |
| Unauthorized request | `test_no_node_route_answers_an_unsigned_caller` (every node route), `test_a_signed_in_human_is_not_a_node`, `test_viewer_and_anonymous_are_refused` |
| Repeated submission | `test_exact_replay_is_refused`, `test_a_second_fresh_submission_for_a_completed_task_is_refused` |
| Safe failure | `test_garbage_headers_never_cause_a_server_error`, `test_errors_never_echo_input`, `test_missing_server_key_is_a_clean_500_without_details` |
| Recovery after restart | `test_replay_is_still_refused_after_a_restart` (state is in the database) |

## 3. Measured quantities (rule-based project)
Coverage, false positives, false negatives and decision latency: [crypto-measurements.md](crypto-measurements.md) (0 false positives in 4,000 honest requests, 0 false negatives in 3,800 attacks of 19 kinds; median 0.14 ms engine, about 7 ms over HTTP). Re-run `python -m fogtrust_crypto.measure` on the machine used for the final report.

## 4. Acceptance criteria

| Criterion | Evidence |
|---|---|
| At least 80 % of automated tests pass | 804 of 804 |
| Zero critical authorization defects | Access matrix (`test_access_matrix.py`, 89 tests), `test_all_node_routes_signed.py`, `security-review-api.md` |
| Zero critical injection defects | ORM only; SQL-looking and Unicode input in every header and field returns a clean refusal (`test_garbage_headers_never_cause_a_server_error`, fuzz tests) |
| Zero secret-exposure defects | `test_secrets_sweep.py` (checked by deliberately adding a leak), `crypto-hardening.md` C5 |
| Zero unsafe file-handling defects | There is no file upload in the system |
| Every report claim links to a test, log or measurement | This table and the evidence documents it names |