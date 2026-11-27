# Test evidence: encrypted results endpoint (FR-5, T4) through Django

Member 2. Date: 2026-11-09. Code: `backend/results/`. Automated tests: `python -m pytest backend/results` (26 tests).
The `results` app has a foreign key to `Task`, so it needs the `tasks` app in `INSTALLED_APPS`. Until `main` registers it, run these tests on a branch that does.

## 1. Automated tests (real endpoint, real database, real engine, real server key file)

| Case | Input | Expected | Test |
|---|---|---|---|
| Honest result | Encrypted result for an assigned task | 201; task `completed`; one valid `TaskResult`; only ciphertext and SHA-256 stored (the plaintext marker appears nowhere in the table); `allow` Decision with the `aes_gcm_tag` rule passed; audit `result.accepted` | `TestAcceptedResult` |
| No leaks | Same | The plaintext marker is in no Decision and no audit event | `test_nothing_secret_reaches_decisions_or_audit` |
| **T4** altered before signing | One ciphertext byte flipped, then signed | 422 `RESULT_INTEGRITY_FAILED`; `signature_valid` passed but `aes_gcm_tag` failed; a failed `TaskResult` is kept; the task stays `assigned`; audit event | `test_ciphertext_altered_before_signing_fails_the_integrity_check` |
| T4 | A good result after the tampered one | 201; one valid and one failed row | `test_a_good_result_is_still_accepted_after_a_tampered_one` |
| T4 altered in transit | Ciphertext changed after signing | 401 `NODE_SIGNATURE_INVALID`; nothing stored | `test_ciphertext_altered_in_transit_fails_the_signature` |
| T4 moved | A ciphertext made for another task | 422 `RESULT_INTEGRITY_FAILED` (the task id is part of what GCM checks) | `test_ciphertext_made_for_another_task_is_refused` |
| T4 at rest | Ciphertext edited in the database, then an operator opens the result | `integrity_valid: false`, no result shown, audit `result.integrity_failure_at_rest` | `test_tampering_with_the_stored_ciphertext_is_caught_when_it_is_read` |
| Replay | Exact copy of an accepted submission | 401 `HEARTBEAT_REPLAYED`; one row | `test_exact_replay_is_refused` |
| Repeated submission | A second, freshly signed result for a completed task | 409 `TASK_INVALID_STATE`; still one valid result | `test_a_second_fresh_submission_for_a_completed_task_is_refused` |
| Ownership | Result from a node the task is not assigned to; unknown, malformed or 36-character task ids | 403 `RESULT_NOT_ASSIGNED`, identical answers, no stack trace | `test_task_assigned_to_another_node_is_refused`, `test_unknown_or_malformed_task_ids_look_the_same_as_not_assigned` |
| State | Task still `queued` | 409 `TASK_INVALID_STATE` | `test_queued_task_cannot_receive_a_result` |
| T5 / T1 / stale | Revoked node; spoofed node; timestamp an hour old | 403 `NODE_REVOKED`; 401 `NODE_SIGNATURE_INVALID`; 401 `HEARTBEAT_STALE` | `test_revoked_node_cannot_submit`, `test_spoofed_node_is_refused`, `test_stale_submission_is_refused` |
| T-final size | Body over 66,000 bytes | 413 before the body is read | `test_oversized_body_is_refused_before_it_is_read` |
| T-final malformed | Non-JSON; missing or wrong-typed envelope fields | 400 `MALFORMED_REQUEST` / `VALIDATION_ERROR`; nothing stored | `test_signed_non_json_and_bad_envelopes_are_refused` |
| Safe failure | No server key configured | Plain 500 `INTERNAL_ERROR`; the cause is not in the response; it is in the audit log | `test_missing_server_key_is_a_clean_500_without_details` |
| Rate limit | Third request of a 2/min limit | 429 | `test_rate_limit` |
| Database rules | Two valid results for one task; a failed row with no reason | Rejected by the database; repeated failed attempts allowed | `test_database_allows_one_valid_result_per_task` |
| Viewing | Operator reads the decrypted result; viewer 403; anonymous 401; unknown task 404; every view audited; `no-store` | as listed | `TestViewingResults` (5 tests) |

## 2. Live run (real Django server, real simulator, HTTP)

Part of the 15-step run in [live-demo.md](live-demo.md): steps 10 to 15 are the result steps. State afterwards, read from the database:

```
tasks: 2 completed, 3 still assigned
task results: valid, RESULT_INTEGRITY_FAILED, valid
result decisions: allow x2; deny: RESULT_INTEGRITY_FAILED, NODE_SIGNATURE_INVALID, HEARTBEAT_REPLAYED, TASK_INVALID_STATE (one each)
audit: result.accepted x2, result.rejected x4
```

Limit: AES-GCM does not authenticate who encrypted, so someone with database write access can insert a new, validly encrypted result; editing an existing one is caught. See the threat model, CR-11.