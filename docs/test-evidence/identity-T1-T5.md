# Test evidence: T1 (spoofed node), T5 (revocation), unauthorized requests, T-final (Member 1 part)

Member 1. Tests are in `backend/nodes/tests/`, `backend/accounts/tests/` and `backend/core/tests/`.
"Actual" is what the code returned when the test ran (HTTP status, client error code, and the reason
recorded in the audit log). Reproduce everything with `python -m pytest backend/nodes backend/accounts backend/core`.

## T1: Spoofed node

The client always receives the same generic answer for a token failure (`401 ENROLL_TOKEN_INVALID`,
"Enrollment rejected."), so an attacker cannot tell a real-but-used token from a made-up one.
The precise reason is in the audit event (`node.enroll`, `failure`) and in the Decision (evidence view).

| # | Input | Expected | Actual (client / audit reason) | Evidence (test) | Result |
|---|---|---|---|---|---|
| 1a | Enrollment with no token | Rejected before processing | `400 VALIDATION_ERROR` / `VALIDATION_ERROR`, field names only | `test_a_no_token_is_a_validation_error_and_is_audited` | Pass |
| 1b | Forged token (well-formed, never issued) | Rejected | `401 ENROLL_TOKEN_INVALID` / `ENROLL_TOKEN_INVALID`; rule `token_valid` failed | `test_b_forged_token` | Pass |
| 1c | Expired token | Rejected, reason recorded | `401 ENROLL_TOKEN_INVALID` / `ENROLL_TOKEN_EXPIRED` | `test_c_expired_token` | Pass |
| 1d | Token already used | Rejected, no second node | `401 ENROLL_TOKEN_INVALID` / `ENROLL_TOKEN_USED`; 1 node exists | `test_d_reused_token` | Pass |
| 1d2 | Two requests hold one valid token (race) | Exactly one node | Loser gets `ENROLL_TOKEN_INVALID` / `ENROLL_TOKEN_USED`; its node insert is rolled back | `test_a_stale_token_object_cannot_win_a_race` | Pass |
| 1d3 | Cancelled token | Rejected | `401 ENROLL_TOKEN_INVALID` / `ENROLL_TOKEN_INVALID`, state `cancelled` | `test_cancelled_token` | Pass |
| 1d4 | Compare the client's view of b, c and d | Indistinguishable | One identical error body | `test_the_client_cannot_tell_the_token_failures_apart` | Pass |
| 1e | Valid token, victim's public key, attacker's signature | Rejected | `401 ENROLL_PROOF_INVALID`; `token_valid` passed, `proof_of_possession` failed | `test_someone_elses_public_key_with_my_own_signature` | Pass |
| 1e2 | Proof signed for another name or another token | Rejected | `401 ENROLL_PROOF_INVALID` | `test_proof_signed_for_a_different_name`, `..._token` | Pass |
| 1e3 | A failed attempt must not burn the token | Token still usable | Next honest enrollment: `201` | `test_failed_attempts_do_not_burn_the_token` | Pass |
| 1e4 | Re-using an enrolled node's public key | Rejected | `409 ENROLL_KEY_IN_USE` | `test_a_key_cannot_be_registered_twice` | Pass |
| 1f | Heartbeat with a genuine node id but the attacker's key (real engine, real Node table) | Rejected | `NODE_SIGNATURE_INVALID`; `node_known` passed, `signature_valid` failed | `test_t1f_genuine_node_id_but_the_attackers_own_key` | Pass |
| 1f2 | Heartbeat from an unknown node id | Rejected | `NODE_UNKNOWN` | `test_an_unknown_node_id_is_refused` | Pass |
| 1g | A node borrows another enrolled node's id | Rejected | `NODE_SIGNATURE_INVALID` | `test_a_node_cannot_borrow_another_nodes_identity` | Pass |
| 1h | 12 enrollment attempts in a minute, with a different forged `X-Forwarded-For` each | Throttled | Attempts 11 and 12: `429 RATE_LIMITED`; audited once as `request.rate_limited` | `test_enrollment_is_throttled_per_client`, `test_a_forged_forwarded_for_header_does_not_bypass_the_limit` | Pass |

## T5: Revocation

| # | Input | Expected | Actual | Evidence (test) | Result |
|---|---|---|---|---|---|
| 5.1 | Admin revokes node with reason and the exact node name | Node revoked, who/why/when stored | `200`, `status=revoked`, `revoked_by=admin1`, source `manual` | `test_revocation_response_and_state` | Pass |
| 5.2 | Same action in the audit log and evidence view | One audit event, one Decision | `node.revoke`/`success` with node name, reason, source; Decision `revoke` with 2 rules | `test_it_is_audited_...`, `test_it_is_explained_...` | Pass |
| 5.3 | Heartbeat from the node after revocation (real engine) | Refused on the very next request | `NODE_REVOKED`; counter unchanged | `test_the_next_heartbeat_after_revocation_is_refused` | Pass |
| 5.4 | Revoked node with a bad signature | Status checked before the signature | `NODE_REVOKED` (not `NODE_SIGNATURE_INVALID`) | `test_revocation_is_checked_before_the_signature` | Pass |
| 5.5 | Other nodes after one is revoked | Unaffected | Healthy node's heartbeat accepted | `test_other_nodes_keep_working` | Pass |
| 5.6 | Operator or viewer tries to revoke | Generic denial, nothing changes | `403 PERMISSION_DENIED` "Access denied."; node name not in response; `access.denied` audited | `test_other_roles_get_a_generic_denial_and_nothing_changes` | Pass |
| 5.7 | Wrong, missing or differently-cased confirmation name | Not revoked | `400 CONFIRMATION_REQUIRED`; failure audited | `test_wrong_confirmation_does_nothing`, `test_missing_or_inexact_confirmation` | Pass |
| 5.8 | Revoke twice | Second refused | `409 NODE_ALREADY_REVOKED`; exactly one success event | `test_already_revoked_conflicts` | Pass |
| 5.9 | Revoked node re-enrolls with its old key | Refused (revocation is permanent) | `409 ENROLL_KEY_IN_USE` | `test_a_revoked_node_cannot_re_enroll_with_its_old_key` | Pass |
| 5.10 | Trust engine revokes automatically | Same service, system actor | `revoke_source=automatic`, actor `system/trust-engine` | `test_the_trust_engine_can_revoke_through_the_same_service` | Pass |
| 5.11 | Scheduler hook | Signal sent once, after commit; broken receiver cannot undo revocation | as expected | `test_the_scheduler_hook_fires_once_after_commit`, `test_a_failing_receiver_cannot_undo_the_revocation` | Pass |
| 5.12 | Audit chain after all of the above | Still valid | `valid: true` | `test_the_audit_chain_still_verifies` | Pass |

## Unauthorized request (T-final)

| # | Input | Expected | Actual | Evidence (test) | Result |
|---|---|---|---|---|---|
| U.1 | 12 endpoints x anonymous | `401 AUTH_REQUIRED` | all 12 | `TestAccessMatrix::test_anonymous_is_refused_with_401` | Pass |
| U.2 | 12 endpoints x viewer, operator, admin | Role table from the contract, enforced by the server | 36 combinations behave as the table says; every denial is a generic `403` and an `access.denied` event, and changes nothing | `TestAccessMatrix::test_each_role` | Pass |
| U.3 | A new route is added without being put in the matrix | Test fails | guard test enumerates the URL map | `test_every_route_in_the_api_is_covered_by_this_matrix` | Pass |
| U.4 | CSRF token missing on create-token, revoke, create-user | `403 CSRF_FAILED`, nothing changes | as expected | `test_csrf_is_required` (3 files) | Pass |
| U.5 | Admin demoted or disabled while their session is open | Loses the power on the next request | `403` / `401` | `test_a_demoted_admin_loses_the_power_immediately`, `test_disabling_blocks_an_existing_session_and_new_logins` | Pass |
| U.6 | Admin demotes or disables themselves | Refused (no lock-out) | `409 CONFLICT`, failure audited | `TestAdministratorCannotLockThemselvesOut` | Pass |

## T-final items owned by Member 1

| Item | Result | Evidence |
|---|---|---|
| Oversized input | Enrollment body over 4 KB: `413 PAYLOAD_TOO_LARGE` before parsing, audited. Over-long fields: `400` | `test_body_over_the_enrollment_cap_is_refused_before_parsing`, `test_huge_values_are_refused` |
| Malformed input | Invalid JSON `400 MALFORMED_REQUEST`; non-object JSON, unknown fields `400 VALIDATION_ERROR`; wrong content type `415`; all audited; input never echoed | `TestMalformedAndOversizedInput` |
| Injection | SQL and script text in name, token and search fields: `400`/harmless, tables intact | `test_sql_injection_in_name_and_token_is_harmless`, `test_search_cannot_be_used_for_sql_injection` |
| Repeated submission | A token redeems once; a second revoke is `409` | 1d, 5.8 |
| Safe failure | Validation errors carry no input, stack trace or key; live server log scan found no `password`, `enrollment_token`, `proof` or traceback text | `test_validation_errors_do_not_echo_what_was_sent`; live run below |
| Recovery after restart | Server killed and restarted on the same database: revoked node still revoked, audit chain still valid (12 events) | live run below |

### Live run (real server, `DEBUG=False`, Member 2's node simulator)

1. `POST /auth/login/` as admin: `200`. `POST /enrollment-tokens/`: `201`.
2. `node_sim enroll` with that token: enrolled as a node id. A second simulator with the same token: `HTTP 401 ENROLL_TOKEN_INVALID`.
3. Revoke with a wrong confirmation: `CONFIRMATION_REQUIRED`. With the right name: `200 revoked`. Again: `NODE_ALREADY_REVOKED`.
4. Audit log, in order: `enroll.token_create` success, `node.enroll` success, `node.enroll` failure `ENROLL_TOKEN_USED`, `node.revoke` failure `CONFIRMATION_REQUIRED`, `node.revoke` success, `node.revoke` failure `NODE_ALREADY_REVOKED`. `POST /audit/verify/`: `valid: true`.
5. Server stopped and started again: node still `revoked` with its reason; chain valid.

## Measurements (decision latency)

Single laptop-class machine, SQLite, 200 enrollments then 200 revocations through the real services
(`Decision.latency_ms` is measured inside the decision; "total" includes the audit event and commit).

| Operation | Runs | Decision median | Decision p95 | Decision max | Total median | Total p95 |
|---|---|---|---|---|---|---|
| Enrollment (accepted, 6 rules) | 200 | 2.62 ms | 4.03 ms | 7.36 ms | 4.59 ms | 6.81 ms |
| Revocation | 200 | 1.02 ms | 1.38 ms | 2.91 ms | 3.65 ms | 4.80 ms |

## Defect found and fixed during this work

| | |
|---|---|
| Finding | DRF trusts the client's `X-Forwarded-For` header unless `NUM_PROXIES` is set. Sending a different value with each request defeated the per-IP login limit (12 attempts, no `429`; limit is 5/min). |
| Severity | High for credential guessing (the per-username limit still applied), and it would have applied to enrollment too. |
| Fix | `REST_FRAMEWORK["NUM_PROXIES"] = 0` (env `TRUSTED_PROXY_COUNT`): clients are identified by the socket address only. |
| Regression tests | `test_rotating_x_forwarded_for_cannot_bypass_the_login_limit`, `test_a_forged_forwarded_for_header_does_not_bypass_the_limit` |
