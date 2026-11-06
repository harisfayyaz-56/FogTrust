# Test evidence: T2 (replayed heartbeat) and T4 (altered result)

Member 2. Test names are in `backend/fogtrust_crypto/tests/`. "Actual" values come from running the engine
(`reason_code` and the last rule fired). Run `python -m pytest backend/fogtrust_crypto` to reproduce.

## T2: Replayed heartbeat

| # | Input | Expected | Actual | Evidence (test) | Result |
|---|---|---|---|---|---|
| 2.1 | Valid heartbeat, counter 1, timestamp now | Accepted | `OK`; last rule `counter_increasing` passed | `test_valid_heartbeat_is_accepted_and_advances_state` | Pass |
| 2.2 | The identical captured request sent again | Rejected, nonce reason | `HEARTBEAT_REPLAYED`; rule `nonce_unique`: "nonce already used by this node inside the window". The copy's signature still verifies | `test_T2_exact_replay_is_rejected_with_the_nonce_reason` | Pass |
| 2.3 | Same capture sent 31 s later | Rejected as stale (timestamp is checked before the nonce) | `HEARTBEAT_STALE`; "skew +31.0 s, limit 30 s" | `test_replay_later_than_the_window_is_stale_not_replayed` | Pass |
| 2.4 | Timestamp 100 s old | Rejected | `HEARTBEAT_STALE`; "skew +100.0 s, limit 30 s" | `test_stale_denial_explains_skew_and_limit` | Pass |
| 2.5 | Boundary: skew exactly 30 s / 31 s | Accepted / rejected | as expected | `test_timestamp_window_boundaries` | Pass |
| 2.6 | Valid signature, counter equal or lower than the last | Rejected | `HEARTBEAT_COUNTER_REGRESSED`; evidence `counter`, `last_counter` | `test_counter_equal_or_lower_is_rejected` | Pass |
| 2.7 | 20 copies of one request at the same moment | Exactly one accepted | 1 accepted, 19 `HEARTBEAT_REPLAYED` | `test_identical_requests_sent_at_the_same_moment_are_accepted_exactly_once` | Pass |
| 2.8 | End to end: simulator `replayer` against a local HTTP broker | First 200, then 409 | 200 `OK`, then 409 `HEARTBEAT_REPLAYED` (twice) | `test_T2_replayer_is_accepted_once_then_rejected` | Pass |
| 2.9 | Rejected requests change nothing | Store empty or unchanged | no nonce stored, counter unchanged | `test_stale_heartbeat_leaves_the_store_untouched`, `test_bad_signature_cannot_fill_the_nonce_store` | Pass |

## T4: Altered result

| # | Input | Expected | Actual | Evidence (test) | Result |
|---|---|---|---|---|---|
| 4.1 | Honest result, 33 bytes | Decrypted, hash stored | `OK`; rule `aes_gcm_tag` passed | `test_round_trip` | Pass |
| 4.2 | One ciphertext byte flipped (first, middle, last/tag) | Integrity failure, no plaintext | `RESULT_INTEGRITY_FAILED`; "authentication tag does not match"; plaintext `None` | `test_T4_one_flipped_ciphertext_byte_is_detected` | Pass |
| 4.3 | Ciphertext altered before the node signs (signature valid) | Integrity failure | `RESULT_INTEGRITY_FAILED`, with `signature_valid` passed | `test_T4_altered_ciphertext_with_a_valid_signature_fails_integrity` | Pass |
| 4.4 | Ciphertext altered in transit (after signing) | Signature failure | `NODE_SIGNATURE_INVALID` | `test_T4_ciphertext_altered_in_transit_fails_the_signature` | Pass |
| 4.5 | Valid ciphertext submitted for another task or attributed to another node | Integrity failure | `RESULT_INTEGRITY_FAILED` | `test_ciphertext_moved_to_another_task_is_detected`, `test_ciphertext_attributed_to_another_node_is_detected` | Pass |
| 4.6 | Altered nonce, swapped ephemeral key, wrong server key | Integrity failure | `RESULT_INTEGRITY_FAILED` | `test_altered_nonce_is_detected`, `test_swapped_ephemeral_key_is_detected`, `test_wrong_server_key_fails_integrity` | Pass |
| 4.7 | Malformed envelope (extra or missing field, bad base64, short ciphertext, all-zero key) | Safe refusal | `VALIDATION_ERROR`, no exception | `test_malformed_envelopes_fail_safely` | Pass |
| 4.8 | Ciphertext over 65,536 characters | Refused before decoding | `PAYLOAD_TOO_LARGE` | `test_oversized_ciphertext_is_refused_before_decoding` | Pass |
| 4.9 | End to end: simulator `tamper_ciphertext` against a local HTTP broker | 422 integrity failure, nothing stored | 422 `RESULT_INTEGRITY_FAILED`, no plaintext stored | `test_T4_altered_ciphertext_is_rejected_with_the_integrity_reason` | Pass |

## Measurements (decision latency)

Single machine, pure Python, in-memory store, no network. These are engine times only, not request times.

| Operation | Runs | Median | 95th percentile | Max |
|---|---|---|---|---|
| Heartbeat verification (accepted, all 8 checks) | 2,000 | 0.140 ms | 0.181 ms | 0.909 ms |
| Result decryption (1 KB plaintext) | 1,000 | 0.057 ms | 0.087 ms | 0.207 ms |

False positives (honest request wrongly rejected) and false negatives (attack accepted) for this slice: 0 and 0 across
the cases above and the end-to-end attacker tests. These counts are for the listed cases only, not a general claim.