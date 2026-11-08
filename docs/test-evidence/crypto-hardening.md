# Test evidence: hardening (Week 4, Part C) and measurements (Part D)

Member 2. Date: 2026-11-07. Run `python -m pytest backend/fogtrust_crypto` to reproduce C1, C2 (engine part) and C5.
Measurements are in [crypto-measurements.md](crypto-measurements.md).

| Task | Status | Where |
|---|---|---|
| C1 Fuzzing | Done | `tests/test_fuzz.py` |
| C2 Size limits and safe errors | Engine part done; endpoint tests wait for the endpoints | below |
| C3 Timing of early exits | Done, decision recorded | `crypto-measurements.md` section C3; spec section 8 |
| C4 Dependency audit | Done | below |
| C5 Secrets sweep | Done against the crypto package and stub broker; repeat against Django when the endpoints exist | `tests/test_secrets_sweep.py` |
| D1 to D3 Measurements | Done against the stub broker; HTTP numbers to be repeated against Django | `measure.py`, `test_measure.py` |

## C1. Fuzzing

Nine tests, 2,500 inputs each (about 22,500 in all, 1.4 s, fixed seed 20261107, so any failure repeats exactly). They cover mutated heartbeats and result submissions (one header, the body, the path or the method changed at a time), random garbage headers and bodies (including non-string values), validly signed bodies with random content, random result envelopes, and the small parsers (public keys, enrollment proof, string to sign).

Properties checked on every input: nothing raises; a mutated request is never accepted; every result has a known reason code and a decision that can be written as JSON.

| Finding | How it was found | Fix | Regression test |
|---|---|---|---|
| The node id was accepted in upper case (and braces, no hyphens, `urn:uuid:`), so one request had many valid spellings | Fuzz: the first mutated request that was accepted | Only a lower-case hyphenated UUID is accepted | `test_uppercase_node_id_is_not_accepted_as_the_same_node`, `test_other_uuid_spellings_are_not_accepted` |
| `build_string_to_sign` raised `TypeError` (not `ValueError`) when the method was a dict or list | Fuzz: crash | The method is type-checked first | `test_non_string_method_raises_value_error_not_type_error` |
| A timestamp with leading zeros (`01763547631`) verified as the same request | Same class as the first finding; fixed in the same change, not separately found by the fuzz | Canonical decimal only | `test_timestamp_with_leading_zeros_is_not_accepted` |
| A signature with different unused trailing bits in its last base64 character decodes to the same bytes (16 spellings of one signature) | Same class; fixed in the same change | Canonical base64 only | `test_signature_with_non_canonical_base64_is_not_accepted` |

After the fixes: 0 mutated requests accepted, 0 crashes. Limit: a fuzz run is evidence, not proof; it has not covered body formats beyond the ones listed.

## C2. Size limits and safe errors

| Check | Result |
|---|---|
| Heartbeat body limit 2 KB, result body limit 66,000 bytes, ciphertext 65,536 base64 characters | Enforced in the engine before any crypto (`PAYLOAD_TOO_LARGE`). Tests: `test_oversized_body_is_refused_before_any_crypto`, `test_oversized_body_is_refused_before_crypto`, `test_oversized_ciphertext_is_refused_before_decoding` |
| Refuse on `Content-Length` before reading the body | `declared_length_too_large()` added (missing header is allowed, a non-number is refused). Test: `test_declared_length_check`. **The view that calls it comes with the endpoints** |
| Django-wide limit | `DATA_UPLOAD_MAX_MEMORY_SIZE` is 256 KB in `settings.py`; the exception handler maps it to `PAYLOAD_TOO_LARGE` (Member 1, `core/exceptions.py`) |
| No stack traces, no echoed input | Member 1's handler returns the standard envelope with a request id and logs unexpected errors server-side only. Engine messages are fixed sentences; tests assert they do not contain input |
| **Not yet done** | Test-client tests against my own endpoints (oversized body, malformed JSON, a deliberately raised error) land with Part A |

## C3. Timing of early exits

Engine: unknown node 6.2 µs, revoked node 6.4 µs, wrong key 106.8 µs (3,000 interleaved runs each). Over loopback HTTP the unknown and revoked cases were about 125 µs faster. The difference is measurable but the specific error code already reveals the same thing. **Decision: accepted, with reasons** (threat model CR-7, spec section 8). Full tables are in `crypto-measurements.md`.

## C4. Dependency audit

`pip-audit` 2.10.1, 2026-11-07, against the pinned `requirements.txt` and `requirements-dev.txt`: **No known vulnerabilities found** in both. Limit: pip-audit only knows published advisories, so this says nothing about unreported flaws. Re-run before the final submission.

## C5. Secrets sweep

`test_no_secret_appears_anywhere_a_person_or_a_log_could_see_it` runs a whole session (key generation, enrollment proof, every heartbeat attacker twice, every result behaviour twice, dry runs, key-handling errors) and searches every Decision, every result `repr`, every HTTP response, all command-line output, all log records and the text of every key error for: the node private key, the server private key, the enrollment token, the result plaintext, every signature sent, and the enrollment proof. None found.

**The sweep was checked by mutation:** adding the plaintext to a decision's evidence made the test fail with "result plaintext leaked"; with the change removed it passes again.

Not covered yet: Django's own request logs and the audit log (Member 1's redaction), because the endpoints do not exist yet. Repeat the sweep against the real server.